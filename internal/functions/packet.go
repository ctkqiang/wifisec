package functions

// IsWifiConnected 判断本机当前是否已连接任意 Wi-Fi。
// 三个网络子命令各自独立成文件：devices.go（设备发现）、
// portscan.go（端口扫描）、sniff.go（抓包导出 pcap）。
func IsWifiConnected() bool {
	return false
}
