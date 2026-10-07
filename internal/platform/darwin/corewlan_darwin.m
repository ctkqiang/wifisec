// CoreWLAN / CoreLocation 的 Objective-C 实现。
//
// 设计要点：
//   - 仅导出纯 C ABI（无 Objective-C 符号泄漏到 Go 侧），由同目录 Go 文件经 cgo 调用；
//   - 返回扫描结果使用 JSON 字符串，避免为每条记录维护 C 结构体生命周期；
//   - 字符串一律 strdup 出参，所有权移交调用方（Go 侧用 free 释放）；
//   - 授权请求依赖 NSRunLoop 驱动 delegate 回调，因此请求期间显式运转当前 RunLoop。

#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#import <CoreWLAN/CoreWLAN.h>
#import <CoreLocation/CoreLocation.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

// WifisecLocationDelegate 在授权状态脱离“未决定”时结束 RunLoop 等待。
// CLLocationManager 的 delegate 为 weak 引用，故由调用方持有强引用直至请求结束。
@interface WifisecLocationDelegate : NSObject <CLLocationManagerDelegate>
@property (nonatomic, assign) BOOL finished;
@end

@implementation WifisecLocationDelegate

- (void)locationManagerDidChangeAuthorization:(CLLocationManager *)manager {
    if (manager.authorizationStatus != kCLAuthorizationStatusNotDetermined) {
        self.finished = YES;
    }
}

@end

#pragma clang diagnostic pop

// wifisec_location_status 返回当前进程的定位授权状态；
// 系统定位总开关关闭时按 restricted 处理。
int wifisec_location_status(void) {
    if (![CLLocationManager locationServicesEnabled]) {
        return 1;
    }

    return (int)[[CLLocationManager alloc] init].authorizationStatus;
}

// wifisec_location_request 在状态为“未决定”时触发系统授权弹窗，
// 并运转 RunLoop 最多 timeout_sec 秒等待用户选择；状态已确定时直接返回，不弹窗。
int wifisec_location_request(int timeout_sec) {
    if (timeout_sec < 1) {
        timeout_sec = 1;
    }

    // 无窗口 CLI 进程必须显式完成 NSApplication 启动并置为 Accessory，
    // 否则 LaunchServices 视其为“启动中”，TCC 授权弹窗被系统抑制，
    // 授权回调永远等不到用户输入，进程只能挂起到超时。
    NSApplication *application = [NSApplication sharedApplication];
    [application setActivationPolicy:NSApplicationActivationPolicyAccessory];
    [application finishLaunching];

    CLLocationManager *manager = [[CLLocationManager alloc] init];
    if (manager.authorizationStatus != kCLAuthorizationStatusNotDetermined) {
        return (int)manager.authorizationStatus;
    }

    WifisecLocationDelegate *delegate = [[WifisecLocationDelegate alloc] init];
    manager.delegate = delegate;
    [manager startUpdatingLocation];
    [manager requestAlwaysAuthorization];

    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:timeout_sec];
    NSDate *step = nil;

    // delegate 回调只是加速器：无 App 事件循环时它不一定被投递，
    // 因此每 0.2s 轮询一次状态，保证用户点完“允许”后循环必然退出。
    while (!delegate.finished && manager.authorizationStatus == kCLAuthorizationStatusNotDetermined) {
        step = [NSDate dateWithTimeIntervalSinceNow:0.2];
        if ([step compare:deadline] == NSOrderedDescending) {
            break;
        }
        [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:step];
    }

    return (int)manager.authorizationStatus;
}

// wifisec_cw_scan 调用 CoreWLAN 主动扫描，返回 UTF-8 JSON 字符串。
// 成功时 *err_msg 置 NULL；失败时返回 NULL 并经 *err_msg 给出人类可读错误。
const char *wifisec_cw_scan(char **err_msg) {
    NSError *error = nil;
    CWInterface *interface = [CWWiFiClient sharedWiFiClient].interface;
    if (interface == nil) {
        if (err_msg != NULL) {
            *err_msg = strdup("找不到 Wi-Fi 接口，请确认无线网卡已启用");
        }
        return NULL;
    }

    NSSet<CWNetwork *> *networks = [interface scanForNetworksWithName:nil error:&error];
    if (networks == nil) {
        if (err_msg != NULL) {
            NSString *message = error.localizedDescription ?: @"CoreWLAN 扫描失败";
            *err_msg = strdup(message.UTF8String);
        }
        return NULL;
    }

    NSMutableArray *items = [NSMutableArray arrayWithCapacity:networks.count];
    for (CWNetwork *network in networks) {
        [items addObject:@{
            @"ssid": network.ssid ?: @"",
            @"bssid": network.bssid ?: @"",
            @"channel": @(network.wlanChannel.channelNumber),
            @"rssi": @(network.rssiValue),
        }];
    }

    NSData *json = [NSJSONSerialization dataWithJSONObject:items options:0 error:nil];
    NSString *jsonText = [[NSString alloc] initWithData:json encoding:NSUTF8StringEncoding];

    if (err_msg != NULL) {
        *err_msg = NULL;
    }

    return strdup(jsonText.UTF8String);
}

// wifisec_free 释放 strdup 移交出来的字符串。
void wifisec_free(void *pointer) {
    free(pointer);
}
