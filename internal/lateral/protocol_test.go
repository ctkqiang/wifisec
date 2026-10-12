// protocol_test.go 白盒测试帧编解码与 HMAC 认证：
// 与被测函数同包，直接覆盖未导出的 writeFrame/readFrame/握手路径。
package lateral

import (
	"bytes"
	"errors"
	"net"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	cases := []struct {
		name    string
		payload []byte
	}{
		{name: "空载荷-结束标记", payload: []byte{}},
		{name: "单字节", payload: []byte{0x07}},
		{name: "普通命令", payload: []byte("uname -a")},
		{name: "含中文与换行", payload: []byte("echo '你好\n世界'")},
		{name: "64KB 输出块", payload: bytes.Repeat([]byte{0xAA}, 64*1024)},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			reader, writer := net.Pipe()
			defer reader.Close()
			defer writer.Close()

			go func() {
				_ = writeFrame(writer, testCase.payload)
			}()

			got, err := readFrame(reader, len(testCase.payload)+16)
			if err != nil {
				t.Fatalf("读帧失败：%v", err)
			}

			if !bytes.Equal(got, testCase.payload) {
				t.Fatalf("帧内容不一致：got %d 字节, want %d 字节", len(got), len(testCase.payload))
			}
		})
	}
}

func TestReadFrameTooLarge(t *testing.T) {
	reader, writer := net.Pipe()
	defer reader.Close()
	defer writer.Close()

	// 声称 2MB 载荷但永远不写正文：读取方必须在读载荷前拒绝，
	// 否则畸形长度字段会把内存吃光。
	go func() {
		_, _ = writer.Write([]byte{0x00, 0x20, 0x00, 0x00})
	}()

	if _, err := readFrame(reader, MaxCommandLen); err == nil {
		t.Fatal("超限帧未被拒绝")
	}
}

func TestAuthSuccess(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	errChannel := make(chan error, 2)

	go func() { errChannel <- serverAuth(server, "lab-token") }()
	go func() { errChannel <- clientAuth(client, "lab-token") }()

	for range 2 {
		if err := <-errChannel; err != nil {
			t.Fatalf("认证应当通过，实际：%v", err)
		}
	}
}

func TestAuthFailure(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	errChannel := make(chan error, 2)

	go func() { errChannel <- serverAuth(server, "real-token") }()
	go func() { errChannel <- clientAuth(client, "wrong-token") }()

	sawAuthFailure := false

	for range 2 {
		switch err := <-errChannel; {
		case err == nil:
			// 一侧先返回 nil（clientAuth 在服务端确认前读完状态即走）属正常
		case errors.Is(err, ErrAuthFailed):
			sawAuthFailure = true
		default:
			t.Fatalf("意外的错误类型：%v", err)
		}
	}

	if !sawAuthFailure {
		t.Fatal("令牌不匹配应触发 ErrAuthFailed")
	}
}
