//go:build darwin

// 平台适配器：经 cgo 调用 macOS CoreWLAN / CoreLocation。
//
// LDFLAGS 中的 -sectcreate 把同目录 Info.plist 嵌入最终 Mach-O 的
// __TEXT,__info_plist 段，TCC 据此读取 Bundle ID 与定位用途文案，
// 裸 CLI 才有资格触发系统授权弹窗。链接改写后必须重新 ad-hoc 签名，
// 该步骤由 Makefile 的 build 目标统一完成，保证 clone 后开箱可复现。
package darwin

/*
#cgo CFLAGS: -x objective-c -fmodules -fobjc-arc
#cgo LDFLAGS: -framework Foundation -framework AppKit -framework CoreWLAN -framework CoreLocation
#cgo LDFLAGS: -Wl,-sectcreate,__TEXT,__info_plist,${SRCDIR}/Info.plist

#include <stdlib.h>

int wifisec_location_status(void);
int wifisec_location_request(int timeout_sec);
const char *wifisec_cw_scan(char **err_msg);
void wifisec_free(void *pointer);
*/
import "C"

import (
	"encoding/json"
	"errors"
	"time"
	"unsafe"
)

// LocationStatus 返回当前进程的定位授权状态，不触发任何弹窗。
func LocationStatus() AuthorizationStatus {
	return AuthorizationStatus(C.wifisec_location_status())
}

// RequestLocationAuthorization 在尚未决定时触发系统授权弹窗并等待用户选择；
// 状态已确定时立即返回原值，不会打扰用户。
func RequestLocationAuthorization(timeout time.Duration) AuthorizationStatus {
	seconds := int(timeout / time.Second)
	return AuthorizationStatus(C.wifisec_location_request(C.int(seconds)))
}

// ScanNetworks 通过 CoreWLAN 主动扫描周边接入点。
// 未获定位授权时扫描本身仍成功，但每条记录的 BSSID 由系统脱敏为空。
func ScanNetworks() ([]Network, error) {
	var (
		errMessage *C.char
		networks   []Network
	)

	jsonPointer := C.wifisec_cw_scan(&errMessage)
	if jsonPointer == nil {
		defer C.wifisec_free(unsafe.Pointer(errMessage))
		return nil, errors.New(C.GoString(errMessage))
	}
	defer C.wifisec_free(unsafe.Pointer(jsonPointer))

	if err := json.Unmarshal([]byte(C.GoString(jsonPointer)), &networks); err != nil {
		return nil, err
	}

	return networks, nil
}
