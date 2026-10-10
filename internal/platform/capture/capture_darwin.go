//go:build darwin

package capture

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// BPF 单次读取缓冲：一次 read 可能带回多个 bpf_hdr 记录。
const bpfReadBufferSize = 65536

// bpf 设备节点数量上限，/dev/bpf0 起依次尝试直到拿到未被占用的节点。
const bpfDeviceCount = 48

// bpfHeaderSize 是 struct bpf_hdr 在 darwin 上的固定长度：
// bpf_timeval(tv_sec/tv_usec 各 32 位) + caplen + datalen + hdrlen(16 位)。
const bpfHeaderSize = 18

// bpfSource 持有 /dev/bpfN 句柄以及一次 read 尚未消费完的残余记录。
type bpfSource struct {
	file     *os.File
	buffer   []byte
	left     []byte
	linkType uint32
}

// Open 打开一块 BPF 设备并绑定到 ifaceName。
// /dev/bpf* 属主 root、权限 crw-rw----，普通用户打开得到 EACCES，
// 此时明确提示 sudo；设备忙（EBUSY）则继续尝试下一个编号。
func Open(ifaceName string) (Source, error) {
	if _, err := net.InterfaceByName(ifaceName); err != nil {
		return nil, fmt.Errorf("获取接口 %s 失败：%w", ifaceName, err)
	}

	var (
		file *os.File
		path string
	)

	for index := 0; index < bpfDeviceCount; index++ {
		path = fmt.Sprintf("/dev/bpf%d", index)

		device, err := os.OpenFile(path, os.O_RDWR, 0)
		if err == nil {
			file = device

			break
		}

		switch {
		case errors.Is(err, fs.ErrPermission):
			return nil, errors.New("打开 BPF 设备需要 root 权限（请加 sudo 运行）")
		case errors.Is(err, fs.ErrNotExist):
			return nil, fmt.Errorf("无可用的 %s 节点：%w", path, err)
		}
		// EBUSY：该编号已被其他抓包进程占用，继续试下一个。
	}

	if file == nil {
		return nil, errors.New("全部 /dev/bpf* 设备均被占用，请先关闭其他抓包程序")
	}

	source := &bpfSource{
		file:   file,
		buffer: make([]byte, bpfReadBufferSize),
	}

	if err := source.configure(ifaceName); err != nil {
		_ = file.Close()

		return nil, err
	}

	return source, nil
}

// configure 按 libpcap 验证过的顺序完成五个 ioctl：
// 缓冲区大小必须在 BIOCSETIF 之前设置，随后用 BIOCGBLEN 读回
// 内核可能做过的钳制——read 缓冲小于该值会直接得到 EINVAL。
func (source *bpfSource) configure(ifaceName string) error {
	fd := int(source.file.Fd())

	requestedBuffer := uint32(bpfReadBufferSize)
	if err := ioctlPtr(fd, unix.BIOCSBLEN, unsafe.Pointer(&requestedBuffer)); err != nil {
		return fmt.Errorf("BIOCSBLEN 设置失败：%w", err)
	}

	var request [unix.IFNAMSIZ]byte
	copy(request[:], ifaceName)

	if err := ioctlPtr(fd, unix.BIOCSETIF, unsafe.Pointer(&request[0])); err != nil {
		return fmt.Errorf("BIOCSETIF 绑定 %s 失败：%w", ifaceName, err)
	}

	// BIOCIMMEDIATE 的参数是 u_int 指针，不能用“值即参数”的 IoctlSetInt。
	immediate := uint32(1)
	if err := ioctlPtr(fd, unix.BIOCIMMEDIATE, unsafe.Pointer(&immediate)); err != nil {
		return fmt.Errorf("BIOCIMMEDIATE 设置失败：%w", err)
	}

	timeout := unix.Timeval{Usec: 500000}
	if err := ioctlPtr(fd, unix.BIOCSRTIMEOUT, unsafe.Pointer(&timeout)); err != nil {
		return fmt.Errorf("BIOCSRTIMEOUT 设置失败：%w", err)
	}

	bufferLength, err := unix.IoctlGetInt(fd, unix.BIOCGBLEN)
	if err != nil || bufferLength <= 0 {
		bufferLength = bpfReadBufferSize
	}
	source.buffer = make([]byte, bufferLength)

	linkType, err := unix.IoctlGetInt(fd, unix.BIOCGDLT)
	if err != nil || linkType <= 0 {
		source.linkType = LinkTypeEthernet
	} else {
		source.linkType = uint32(linkType)
	}

	return nil
}

// ioctlPtr 是带指针参数的 ioctl 调用的统一封装。
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

// Read 返回一帧；一次内核 read 得到的多条记录由 left 切片顺序消费，
// BIOCSRTIMEOUT 到期且没有数据时 read 返回 n==0，映射为空闲周期。
func (source *bpfSource) Read() ([]byte, error) {
	if len(source.left) == 0 {
		n, err := source.file.Read(source.buffer)
		if err != nil {
			return nil, fmt.Errorf("读取 BPF 设备失败：%w", err)
		}

		if n == 0 {
			return nil, ErrReadTimeout
		}

		source.left = source.buffer[:n]
	}

	if len(source.left) < bpfHeaderSize {
		source.left = nil

		return nil, ErrReadTimeout
	}

	captured := binary.LittleEndian.Uint32(source.left[8:12])
	headerLen := int(binary.LittleEndian.Uint16(source.left[16:18]))

	frameEnd := headerLen + int(captured)
	if frameEnd > len(source.left) {
		source.left = nil

		return nil, errors.New("BPF 记录长度越界")
	}

	frame := source.left[headerLen:frameEnd]

	// BPF_WORDALIGN：xnu 固定按 sizeof(int32_t)=4 字节对齐下一条记录，
	// 与用户态位数无关；错用 8 会在一次 read 含多记录时错位并越界。
	consumed := (frameEnd + 3) &^ 3
	if consumed >= len(source.left) {
		source.left = nil
	} else {
		source.left = source.left[consumed:]
	}

	return frame, nil
}

// LinkType 返回 BIOCGDLT 查询到的真实链路类型。
func (source *bpfSource) LinkType() uint32 {
	return source.linkType
}

// Close 关闭 BPF 设备节点。
func (source *bpfSource) Close() error {
	return source.file.Close()
}
