//go:build darwin

package writer

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// bpf 设备节点数量上限与读取缓冲等约束一致：/dev/bpf0 起依次尝试。
const bpfDeviceCount = 48

// bpfWriter 持有以 O_RDWR 打开的 BPF 句柄；write() 即注入完整以太网帧。
type bpfWriter struct {
	file *os.File
}

// open 在指定网卡上打开 BPF 写通道。macOS 的 BPF 设备天然读写一体，
// 以 O_RDWR 打开并绑定接口后，file.Write 就是一次内核级帧注入。
func open(ifaceName string) (Port, error) {
	if _, err := net.InterfaceByName(ifaceName); err != nil {
		return nil, fmt.Errorf("获取接口 %s 失败：%w", ifaceName, err)
	}

	var file *os.File

	for index := 0; index < bpfDeviceCount; index++ {
		device, err := os.OpenFile(fmt.Sprintf("/dev/bpf%d", index), os.O_RDWR, 0)
		if err == nil {
			file = device

			break
		}

		switch {
		case errors.Is(err, fs.ErrPermission):
			return nil, errors.New("打开 BPF 设备需要 root 权限（请加 sudo 运行）")
		case errors.Is(err, fs.ErrNotExist):
			return nil, fmt.Errorf("系统没有可用的 BPF 设备节点：%w", err)
		}
		// EBUSY：该编号已被其他进程占用，继续试下一个。
	}

	if file == nil {
		return nil, errors.New("全部 /dev/bpf* 设备均被占用，请先关闭其他抓包程序")
	}

	writer := &bpfWriter{file: file}

	if err := writer.bind(ifaceName); err != nil {
		_ = file.Close()

		return nil, err
	}

	return writer, nil
}

// bind 把 BPF 句柄绑定到指定网卡；与 capture 包的 ioctl 顺序约定一致。
func (writer *bpfWriter) bind(ifaceName string) error {
	fd := int(writer.file.Fd())

	var request [unix.IFNAMSIZ]byte
	copy(request[:], ifaceName)

	if err := ioctlPtr(fd, unix.BIOCSETIF, unsafe.Pointer(&request[0])); err != nil {
		return fmt.Errorf("BIOCSETIF 绑定 %s 失败：%w", ifaceName, err)
	}

	return nil
}

// Write 注入一帧完整以太网帧。
func (writer *bpfWriter) Write(frame []byte) error {
	_, err := writer.file.Write(frame)
	return err
}

// Close 释放 BPF 句柄。
func (writer *bpfWriter) Close() error {
	return writer.file.Close()
}

// ioctlPtr 是带指针参数的 ioctl 调用的统一封装。
// BIOCSETIF 的参数是 ifreq 结构指针，不能按值传递。
func ioctlPtr(fd int, request uint, arg unsafe.Pointer) error {
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(fd),
		uintptr(request),
		uintptr(arg),
	)
	if errno != 0 {
		return errno
	}

	return nil
}
