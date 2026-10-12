// Package lateral 实现局域网横向移动（Client-to-Client）通道：
// 被控端 wifisec agent 监听 TCP，控制端 wifisec shell 连接后
// 以「HMAC 挑战应答 + 长度前缀帧」的极简协议下发命令。
//
// 协议时序（WFS1）：
//
//	agent → client : "WFS1" 魔数 + 16 字节随机 nonce
//	client → agent : 32 字节 HMAC-SHA256(令牌, 魔数+nonce)
//	agent → client : 1 字节认证状态（0=通过）
//	client → agent : 帧(命令文本)
//	agent → client : 帧(输出块)... 帧(空)=输出结束, 帧(1字节)=退出码
//
// 安全设计：
//   - 令牌不落网：认证走 HMAC 挑战应答，抓包重放无效；
//   - 无认证即无服务：agent 空令牌时自动生成随机令牌并打印，
//     防止局域网第三方扫到端口后直接白嫖命令执行；
//   - 帧长有上限：命令 4KB、输出块 1MB，畸形长度字段无法撑爆内存。
package lateral

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// 协议常量。DefaultPort 选 9485 避开常见服务端口，
// 降低与目标机现有服务冲突的概率。
const (
	// magicLen 与魔数 "WFS1"：握手首包用于确认对端是本协议实现，
	// 防止把 HTTP 响应误当认证流程解析。
	magic    = "WFS1"
	nonceLen = 16

	// MaxCommandLen 限制单条命令长度：shell 命令超过 4KB 已无实际意义，
	// 纯粹是DoS或注入超长载荷的信号。
	MaxCommandLen = 4 * 1024

	// MaxOutputChunk 限制输出块帧长：管道单次写入理论上可超 64KB，
	// 上限放宽到 1MB 只防畸形帧，不防真实输出。
	MaxOutputChunk = 1024 * 1024

	// DefaultPort 是 agent 监听与控制端连接的默认端口。
	DefaultPort = 9485

	// authDeadline 限定握手必须在 10 秒内完成：防止半开连接占用
	// agent 的 accept 资源，也避免客户端对死端口长时间挂起。
	authDeadline = 10 * time.Second
)

// ErrAuthFailed 认证失败：令牌不匹配或握手格式错误。
// 控制端拿到该错误时应提示用户核对 --token，而非重试。
var ErrAuthFailed = errors.New("令牌认证失败")

// writeFrame 写一帧：4 字节大端长度前缀 + 载荷。
// 空载荷是合法帧（输出结束标记），由调用方语义决定。
func writeFrame(w io.Writer, payload []byte) error {
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(payload)))

	if _, err := w.Write(header); err != nil {
		return err
	}

	if len(payload) == 0 {
		return nil
	}

	_, err := w.Write(payload)
	return err
}

// readFrame 读一帧。长度字段超过 max 或载荷不完整按协议错误返回；
// 长度为 0 返回空切片（结束标记），不视为错误。
func readFrame(r io.Reader, max int) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}

	length := binary.BigEndian.Uint32(header)
	if int(length) > max {
		return nil, fmt.Errorf("帧长 %d 超过上限 %d", length, max)
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}

	return payload, nil
}

// authToken 计算 HMAC-SHA256(令牌, 魔数+nonce)。
// 挑战覆盖魔数：不同协议版本即使复用 nonce 也产出不同签名。
func authToken(token string, nonce []byte) []byte {
	mac := hmac.New(sha256.New, []byte(token))
	mac.Write([]byte(magic))
	mac.Write(nonce)
	return mac.Sum(nil)
}

// serverAuth 被控端握手：发挑战、验应答、回状态。
// 失败同样回写状态字节（1），让控制端拿到明确错误而非裸断连。
func serverAuth(conn net.Conn, token string) error {
	defer conn.SetDeadline(time.Time{})

	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("生成挑战 nonce 失败：%w", err)
	}

	conn.SetDeadline(time.Now().Add(authDeadline))

	challenge := append([]byte(magic), nonce...)
	if err := writeFrame(conn, challenge); err != nil {
		return fmt.Errorf("发送挑战失败：%w", err)
	}

	response, err := readFrame(conn, sha256.Size)
	if err != nil {
		return fmt.Errorf("读取认证应答失败：%w", err)
	}

	if !hmac.Equal(response, authToken(token, nonce)) {
		writeFrame(conn, []byte{1})
		return ErrAuthFailed
	}

	return writeFrame(conn, []byte{0})
}

// clientAuth 控制端握手：验魔数、算 HMAC 应答、读状态。
func clientAuth(conn net.Conn, token string) error {
	defer conn.SetDeadline(time.Time{})

	conn.SetDeadline(time.Now().Add(authDeadline))

	challenge, err := readFrame(conn, len(magic)+nonceLen)
	if err != nil {
		return fmt.Errorf("读取挑战失败：%w", err)
	}

	if len(challenge) != len(magic)+nonceLen || string(challenge[:len(magic)]) != magic {
		return ErrAuthFailed
	}

	if err = writeFrame(conn, authToken(token, challenge[len(magic):])); err != nil {
		return fmt.Errorf("发送认证应答失败：%w", err)
	}

	status, err := readFrame(conn, 1)
	if err != nil {
		return fmt.Errorf("读取认证状态失败：%w", err)
	}

	if len(status) != 1 || status[0] != 0 {
		return ErrAuthFailed
	}

	return nil
}
