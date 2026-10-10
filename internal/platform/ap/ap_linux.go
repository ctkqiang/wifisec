//go:build linux && !android

package ap

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	platformlinux "github.com/ctkqiang/wifisec/internal/platform/linux"
)

const (
	// apEnabledTimeout 覆盖 hostapd 拉起到 AP-ENABLED 的窗口；
	// 常规驱动亚秒级完成，部分 USB 网卡的慢驱动可能需要数秒。
	apEnabledTimeout = 15 * time.Second

	// terminateGrace 是 SIGTERM 后等待 hostapd 自行退出的宽限期，
	// 超时强制 Kill，避免僵尸进程长期占用无线接口。
	terminateGrace = 3 * time.Second

	// eventBuffer 缓冲接入/离开事件；消费端是会话主循环，
	// 突发大量设备同时接入时缓冲可防止发送端阻塞在无消费者的事件上。
	eventBuffer = 16
)

// Host 在本机无线接口上经 hostapd 承载克隆 AP。
// 生命周期：New 选接口 → Up 拉起进程并阻塞到 AP-ENABLED →
// StationEvents 监听客户端 → Down 终止进程并清理。
type Host struct {
	iface      string
	phy        string
	configPath string
	cmd        *exec.Cmd
	pw         *os.File
	events     chan StationEvent
	stopCh     chan struct{}
	downOnce   sync.Once
}

// New 校验运行环境并选定承载克隆 AP 的无线接口。
// hostapd 配置接口与运行 AP 模式都需要 root；接口从 sysfs 枚举结果中
// 取第一块，优先 managed 模式（iw 缺失时 Mode 为空，同样接受）。
func New() (*Host, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("本机热点克隆需要 root 权限（hostapd 需配置无线接口），请使用 sudo 运行")
	}
	if _, err := exec.LookPath("hostapd"); err != nil {
		return nil, errors.New("未找到 hostapd，请先安装发行版的 hostapd 包（如 apt install hostapd）；或插入 ESP 协处理器走硬件路径")
	}

	ifaces := platformlinux.DiscoverInterfaces(true)
	if len(ifaces) == 0 {
		return nil, errors.New("未发现无线网卡，无法承载克隆热点")
	}

	pick := ifaces[0]
	for _, itf := range ifaces {
		if itf.Mode == "managed" {
			pick = itf
			break
		}
	}

	return &Host{
		iface:  pick.Name,
		phy:    pick.PHY,
		events: make(chan StationEvent, eventBuffer),
		stopCh: make(chan struct{}),
	}, nil
}

// Interface 返回承载克隆 AP 的无线接口名，供上层在 hostapd 接管前
// 对同一接口做扫描（定位真实 AP 的信道与 BSSID）。
func (h *Host) Interface() string {
	return h.iface
}

// Up 生成 hostapd 配置并拉起克隆 AP，阻塞到 AP-ENABLED 才返回。
// 密码非空即 WPA2-PSK（CCMP），为空即开放网络；SSID/密码的字节长度
// 与内容合法性（换行、控制字符）由应用层按 802.11 规则校验。
// 返回值是克隆网络的 BSSID——hostapd 拉起 AP 后接口 MAC 即其地址。
func (h *Host) Up(ssid, password string, channel int) (string, error) {
	if h.cmd != nil {
		return "", errors.New("克隆 AP 已在运行，请先执行 down 再重新拉起")
	}

	configPath, err := h.writeConfig(ssid, password, channel)
	if err != nil {
		return "", err
	}
	h.configPath = configPath

	// 部分驱动在接口 UP 状态下被 hostapd 接管会报 device busy，
	// 先置 DOWN 再启动；失败不致命，hostapd 自身会再尝试拉起。
	_ = exec.Command("ip", "link", "set", "dev", h.iface, "down").Run()

	cmd := exec.Command("hostapd", configPath)
	pr, pw, err := os.Pipe()
	if err != nil {
		return "", fmt.Errorf("创建日志管道失败：%w", err)
	}
	// stdout/stderr 合流到同一管道，由单个 goroutine 统一解析，
	// 避免两条流的事件行交错时需要额外的行序处理。
	cmd.Stdout = pw
	cmd.Stderr = pw

	if err = cmd.Start(); err != nil {
		_ = pw.Close()
		_ = pr.Close()
		return "", fmt.Errorf("启动 hostapd 失败：%w", err)
	}
	h.cmd = cmd
	h.pw = pw

	enabled := make(chan error, 1)
	go h.pumpLogs(pr, enabled)

	select {
	case err := <-enabled:
		if err != nil {
			_ = h.Down()
			return "", err
		}
	case <-time.After(apEnabledTimeout):
		_ = h.Down()
		return "", fmt.Errorf("等待 hostapd 启动超时（%s）；请确认网卡支持 AP 模式（iw list 输出的 supported interface modes 含 AP）", apEnabledTimeout)
	}

	if mac := h.apMAC(); mac != "" {
		return mac, nil
	}
	return "未知", nil
}

// Down 终止 hostapd 进程并清理临时配置；幂等，可在任意阶段调用。
// 关闭 stopCh 让事件泵退出，事件流随之关闭，会话循环得以收尾。
func (h *Host) Down() error {
	h.downOnce.Do(func() {
		close(h.stopCh)

		if h.cmd != nil && h.cmd.Process != nil {
			_ = h.cmd.Process.Signal(syscall.SIGTERM)
			done := make(chan struct{})
			go func() {
				_ = h.cmd.Wait()
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(terminateGrace):
				_ = h.cmd.Process.Kill()
				<-done
			}
		}

		if h.pw != nil {
			_ = h.pw.Close()
		}
		if h.configPath != "" {
			_ = os.Remove(h.configPath)
			h.configPath = ""
		}
		h.cmd = nil
	})

	return nil
}

// StationEvents 返回客户端接入/离开事件流；Down 之后流关闭。
func (h *Host) StationEvents() <-chan StationEvent {
	return h.events
}

// KickWriter 在第二块无线网卡上创建 monitor 接口作为 deauth 注入器。
// hostapd 独占 AP 接口，同一块网卡无法既当 AP 又发自由帧，
// kick 能力因此依赖一块额外的无线网卡（USB 小网卡即可）。
// 返回的 KickInjector 由调用方 Close（会一并删除 monitor 接口）。
func (h *Host) KickWriter() (KickInjector, error) {
	var phy string
	for _, itf := range platformlinux.DiscoverInterfaces(true) {
		if itf.Name == h.iface || itf.PHY == "" || itf.PHY == h.phy {
			continue
		}
		phy = itf.PHY
		break
	}
	if phy == "" {
		return nil, errors.New("未找到第二块无线网卡：hostapd 独占 AP 接口，kick 需要另一块网卡（USB 网卡即可）注入 deauth 帧")
	}

	monitor, err := platformlinux.CreateMonitor(phy)
	if err != nil {
		return nil, err
	}
	if err := platformlinux.SetInterfaceUp(monitor); err != nil {
		_ = platformlinux.DeleteInterface(monitor)
		return nil, err
	}

	injector, err := platformlinux.OpenInjector(monitor)
	if err != nil {
		_ = platformlinux.DeleteInterface(monitor)
		return nil, err
	}

	return &monitorKicker{injector: injector, monitor: monitor}, nil
}

// writeConfig 生成 hostapd 配置落盘为临时文件。
// hostapd 配置值为行内原文（# 仅在行首才是注释），SSID/密码中的
// 换行与控制字符已由应用层校验拦截，这里不做二次转义。
func (h *Host) writeConfig(ssid, password string, channel int) (string, error) {
	lines := []string{
		"driver=nl80211",
		"interface=" + h.iface,
		"ssid=" + ssid,
		"channel=" + strconv.Itoa(channel),
	}
	if password != "" {
		lines = append(lines,
			"wpa=2",
			"wpa_passphrase="+password,
			"wpa_key_mgmt=WPA-PSK",
			"wpa_pairwise=CCMP",
		)
	}

	f, err := os.CreateTemp("", "wifisec-hostapd-*.conf")
	if err != nil {
		return "", fmt.Errorf("创建 hostapd 配置文件失败：%w", err)
	}
	defer f.Close()

	if _, err := f.WriteString(strings.Join(lines, "\n") + "\n"); err != nil {
		return "", fmt.Errorf("写入 hostapd 配置失败：%w", err)
	}

	return f.Name(), nil
}

// pumpLogs 解析 hostapd 输出：启动阶段向 enabled 通报就绪或失败，
// 运行阶段向 events 推送客户端事件；进程退出或 Down 后管道 EOF，
// 关闭事件流以结束会话监听。启动失败的 hostapd 报错往往在退出前的
// 最后几行，等 EOF 统一上报可携带完整诊断信息。
func (h *Host) pumpLogs(pr *os.File, enabled chan<- error) {
	defer close(h.events)
	defer pr.Close()

	ready := false
	scanner := bufio.NewScanner(pr)
	for scanner.Scan() {
		line := scanner.Text()

		if !ready {
			if strings.Contains(line, "AP-ENABLED") {
				ready = true
				enabled <- nil
			}
			continue
		}

		mac, joined, ok := parseStationLine(line)
		if !ok {
			continue
		}
		select {
		case h.events <- StationEvent{MAC: mac, Joined: joined}:
		case <-h.stopCh:
			return
		}
	}

	if ready {
		return
	}
	if err := scanner.Err(); err != nil {
		enabled <- fmt.Errorf("读取 hostapd 日志失败：%w", err)
		return
	}
	enabled <- errors.New("hostapd 进程退出且未达到 AP-ENABLED；常见原因：网卡不支持 AP 模式、信道被法规域禁用、配置字段不被驱动支持")
}

// parseStationLine 识别 hostapd 的客户端事件行：
//
//	wlan0: AP-STA-CONNECTED aa:bb:cc:dd:ee:ff
//	wlan0: AP-STA-DISCONNECTED aa:bb:cc:dd:ee:ff
//
// 前缀（接口名与时间戳）随配置与版本变化，按行内关键词定位最稳。
func parseStationLine(line string) (mac string, joined bool, ok bool) {
	const connected = "AP-STA-CONNECTED "
	const disconnected = "AP-STA-DISCONNECTED "

	if _, rest, found := strings.Cut(line, connected); found {
		return strings.TrimSpace(rest), true, true
	}
	if _, rest, found := strings.Cut(line, disconnected); found {
		return strings.TrimSpace(rest), false, true
	}
	return "", false, false
}

// apMAC 读取接口 MAC；hostapd 拉起 AP 后它就是克隆网络的 BSSID。
func (h *Host) apMAC() string {
	data, err := os.ReadFile("/sys/class/net/" + h.iface + "/address")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// monitorKicker 把第二块网卡的 monitor 接口包装为 KickInjector；
// SetChannel 走 iw 原生命令（iw dev <name> set channel），因此持有接口名。
type monitorKicker struct {
	injector *platformlinux.FrameInjector
	monitor  string
}

func (m *monitorKicker) Write(frame []byte) error {
	return m.injector.Write(frame)
}

func (m *monitorKicker) SetChannel(channel int) error {
	return platformlinux.SetChannel(m.monitor, channel)
}

func (m *monitorKicker) Close() error {
	err := m.injector.Close()
	if delErr := platformlinux.DeleteInterface(m.monitor); err == nil {
		err = delErr
	}
	return err
}
