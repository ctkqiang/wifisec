// client.go 实现控制端：连接被控端、认证后下发命令并收集输出。
//
// 交互模式刻意不做 PTY/raw mode：行级「输入一条 → 回传一条」的
// 语义足够覆盖横向移动场景（查看配置、拉取文件、落地持久化），
// 却避免了 raw 模式在管道/重定向下的全部终端兼容性坑。
package lateral

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

// Client 是控制端会话：一条已认证的 TCP 连接。
type Client struct {
	conn net.Conn
	addr string
}

// Dial 连接被控端并完成认证。连接超时 5 秒、握手超时 10 秒，
// 对局域网内不存在的地址快速失败，不让用户对着黑屏等。
func Dial(addr string, token string) (*Client, error) {
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("连接 %s 失败：%w", addr, err)
	}

	if err := clientAuth(conn, token); err != nil {
		conn.Close()
		return nil, err
	}

	return &Client{conn: conn, addr: addr}, nil
}

// Close 结束会话。
func (client *Client) Close() error {
	return client.conn.Close()
}

// Execute 下发单条命令：发送命令帧，随后循环读帧——
// 非空帧写入 out（实时输出），空帧标记输出结束，其后的
// 1 字节帧是退出码。状态机靠「结束帧之前全是输出」区分
// 1 字节输出块与退出码，协议上不存在歧义。
func (client *Client) Execute(command string, out io.Writer) (int, error) {
	if err := writeFrame(client.conn, []byte(command)); err != nil {
		return 0, fmt.Errorf("发送命令失败：%w", err)
	}

	sawEnd := false

	for {
		frame, err := readFrame(client.conn, MaxOutputChunk)
		if err != nil {
			return 0, fmt.Errorf("连接中断：%w", err)
		}

		switch {
		case sawEnd:
			return int(frame[0]), nil
		case len(frame) == 0:
			sawEnd = true
		default:
			if _, err := out.Write(frame); err != nil {
				return 0, fmt.Errorf("写出失败：%w", err)
			}
		}
	}
}

// Interactive 交互式会话：逐行读取本地输入，回显提示符，
// 输出远端结果。exit/quit/Ctrl-D 结束；空行跳过避免无意义往返。
func (client *Client) Interactive() error {
	input := bufio.NewScanner(os.Stdin)
	input.Buffer(make([]byte, 0, MaxCommandLen), MaxCommandLen)

	prompt := client.addr + "$ "

	for {
		fmt.Print(prompt)

		if !input.Scan() {
			fmt.Println()
			return nil
		}

		command := strings.TrimSpace(input.Text())
		switch command {
		case "":
			continue
		case "exit", "quit":
			return nil
		}

		exitCode, err := client.Execute(command, os.Stdout)
		if err != nil {
			return err
		}

		if exitCode != 0 {
			fmt.Printf("(退出码 %d)\n", exitCode)
		}
	}
}

// IsInteractiveKeyword 判断命令词是否是交互会话关键字：
// bash/sh 让控制端进入交互模式而非把 "bash" 原样发给远端。
func IsInteractiveKeyword(word string) bool {
	return word == "bash" || word == "sh"
}
