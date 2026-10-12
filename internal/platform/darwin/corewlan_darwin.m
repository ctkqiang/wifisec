// CoreWLAN / CoreLocation 的 Objective-C 实现。
//
// 设计要点：
//   - 仅导出纯 C ABI（无 Objective-C 符号泄漏到 Go 侧），由同目录 Go 文件经 cgo 调用；
//   - 返回扫描结果使用 JSON 字符串，避免为每条记录维护 C 结构体生命周期；
//   - 字符串一律 strdup 出参，所有权移交调用方（Go 侧用 free 释放）；
//   - 授权请求依赖 NSRunLoop 驱动 delegate 回调，因此请求期间显式运转当前 RunLoop。
//   - 首次授权时先弹品牌预提示窗（带 WiFi Logo + 说明 + 允许/跳过按钮），
//     用户点「允许」后再触发系统 TCC 弹窗，系统弹窗期间显示状态等待窗。

#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#import <CoreWLAN/CoreWLAN.h>
#import <CoreLocation/CoreLocation.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

// ── 品牌色 ──────────────────────────────────────────────────
// 与 docs/logo.svg / 文档站保持一致的青色系。
static NSColor *BrandCyan(void) {
    return [NSColor colorWithRed:0.00 green:0.72 blue:0.83 alpha:1.0];
}
static NSColor *BrandCyanLight(void) {
    return [NSColor colorWithRed:0.96 green:0.99 blue:1.0 alpha:1.0];
}
static NSColor *BrandCyanDeep(void) {
    return [NSColor colorWithRed:0.0 green:0.58 blue:0.66 alpha:1.0];
}

// ── WiFi Logo 绘制 ──────────────────────────────────────────
// 用 NSBezierPath 程序化绘制，与 docs/logo.svg 视觉一致：
// 青色圆角方牌 + 白色三道弧 + 底部圆点。
static void DrawWifiLogo(NSRect rect) {
    CGFloat minSide = MIN(rect.size.width, rect.size.height);
    NSRect badgeRect = NSMakeRect(
        rect.origin.x + (rect.size.width - minSide) / 2,
        rect.origin.y + (rect.size.height - minSide) / 2,
        minSide, minSide);

    // 圆角方牌底色
    NSBezierPath *badge = [NSBezierPath bezierPathWithRoundedRect:badgeRect
                                                          xRadius:minSide * 0.22
                                                          yRadius:minSide * 0.22];
    [BrandCyan() setFill];
    [badge fill];

    // 玻璃高光（左上角径向渐变模拟）
    NSRect glossRect = badgeRect;
    NSBezierPath *gloss = [NSBezierPath bezierPathWithRoundedRect:glossRect
                                                          xRadius:minSide * 0.22
                                                          yRadius:minSide * 0.22];
    [[[NSColor whiteColor] colorWithAlphaComponent:0.15] setFill];
    [gloss fill];

    // 白色三道弧（从外到内）
    CGFloat cx = NSMidX(badgeRect);
    CGFloat cy = NSMinY(badgeRect) + minSide * 0.28;
    CGFloat arcs[] = {minSide * 0.38, minSide * 0.26, minSide * 0.14};
    for (int i = 0; i < 3; i++) {
        CGFloat r = arcs[i];
        NSBezierPath *arc = [NSBezierPath bezierPath];
        CGFloat startAngle = 30;
        CGFloat endAngle = 150;
        [arc appendBezierPathWithArcWithCenter:NSMakePoint(cx, cy)
                                        radius:r
                                    startAngle:startAngle
                                      endAngle:endAngle
                                     clockwise:NO];
        [[NSColor whiteColor] setStroke];
        [arc setLineWidth:minSide * 0.06];
        [arc stroke];
    }

    // 底部圆点
    CGFloat dotR = minSide * 0.07;
    NSBezierPath *dot = [NSBezierPath bezierPathWithOvalInRect:
        NSMakeRect(cx - dotR, cy - dotR, dotR * 2, dotR * 2)];
    [[NSColor whiteColor] setFill];
    [dot fill];
}

// ── 预提示窗 Controller ─────────────────────────────────────
// 弹出品牌化的 NSWindow，解释为什么需要定位权限，用户选择后再决定是否
// 触发系统 TCC 弹窗。用 modal session 阻塞直到用户点按钮。
@interface WifisecPrePromptController : NSObject <NSWindowDelegate>
@property (nonatomic, strong) NSWindow *window;
@property (nonatomic, assign) BOOL userAllowed;
@property (nonatomic, assign) BOOL finished;
@end

@implementation WifisecPrePromptController

- (instancetype)init {
    self = [super init];
    if (self == nil) {
        return nil;
    }

    // 窗口尺寸：420×280，居中
    NSRect frame = NSMakeRect(0, 0, 420, 280);
    NSUInteger style = NSWindowStyleMaskTitled | NSWindowStyleMaskClosable;
    self.window = [[NSWindow alloc] initWithContentRect:frame
                                              styleMask:style
                                                backing:NSBackingStoreBuffered
                                                  defer:NO];
    [self.window setTitle:@"wifisec"];
    [self.window center];
    [self.window setDelegate:self];
    [self.window setReleasedWhenClosed:NO];

    // 背景色：极浅青
    [self.window setBackgroundColor:BrandCyanLight()];

    // 内容视图
    NSView *content = self.window.contentView;
    [content setWantsLayer:YES];
    [content.layer setBackgroundColor:[BrandCyanLight() CGColor]];

    // Logo 区域（左侧 80×80）
    NSImageView *logoView = [[NSImageView alloc] initWithFrame:NSMakeRect(24, 170, 80, 80)];
    [logoView setImage:[self drawLogoImage]];
    [logoView setImageScaling:NSImageScaleProportionallyUpOrDown];
    [content addSubview:logoView];

    // 标题
    NSTextField *titleLabel = [[NSTextField alloc] initWithFrame:NSMakeRect(120, 230, 270, 28)];
    [titleLabel setStringValue:@"wifisec 需要定位权限"];
    [titleLabel setFont:[NSFont boldSystemFontOfSize:15]];
    [titleLabel setTextColor:BrandCyanDeep()];
    [titleLabel setBezeled:NO];
    [titleLabel setDrawsBackground:NO];
    [titleLabel setEditable:NO];
    [titleLabel setSelectable:NO];
    [content addSubview:titleLabel];

    // 说明文字
    NSTextField *descLabel = [[NSTextField alloc] initWithFrame:NSMakeRect(120, 130, 275, 90)];
    [descLabel setStringValue:@"Apple 将 Wi-Fi 接入点的 BSSID（MAC 地址）归类为精确位置信息。wifisec 需要定位授权才能显示周边 AP 的真实 MAC 地址，未获授权时系统只会返回空值。\n\n点击「允许」后，系统会弹出标准授权对话框。"];
    [descLabel setFont:[NSFont systemFontOfSize:12]];
    [descLabel setTextColor:[NSColor controlTextColor]];
    [descLabel setBezeled:NO];
    [descLabel setDrawsBackground:NO];
    [descLabel setEditable:NO];
    [descLabel setSelectable:NO];
    [descLabel setLineBreakMode:NSLineBreakByWordWrapping];
    [content addSubview:descLabel];

    // 「允许」按钮（蓝色 default）
    NSButton *allowButton = [[NSButton alloc] initWithFrame:NSMakeRect(200, 20, 100, 32)];
    [allowButton setTitle:@"允许"];
    [allowButton setBezelStyle:NSBezelStyleRounded];
    [allowButton setKeyEquivalent:@"\r"];
    [allowButton setTarget:self];
    [allowButton setAction:@selector(allowClicked:)];
    [content addSubview:allowButton];
    [self.window setInitialFirstResponder:allowButton];

    // 「跳过」按钮（灰色）
    NSButton *skipButton = [[NSButton alloc] initWithFrame:NSMakeRect(310, 20, 80, 32)];
    [skipButton setTitle:@"跳过"];
    [skipButton setBezelStyle:NSBezelStyleRounded];
    [skipButton setKeyEquivalent:@"\e"];
    [skipButton setTarget:self];
    [skipButton setAction:@selector(skipClicked:)];
    [content addSubview:skipButton];

    return self;
}

// 用 NSImage + NSBitmapImageRep 绘制 Logo，返回可供 NSImageView 显示的位图。
- (NSImage *)drawLogoImage {
    NSInteger size = 80;
    NSImage *image = [[NSImage alloc] initWithSize:NSMakeSize(size, size)];
    [image lockFocus];
    DrawWifiLogo(NSMakeRect(0, 0, size, size));
    [image unlockFocus];
    return image;
}

- (void)allowClicked:(NSButton *)sender {
    self.userAllowed = YES;
    self.finished = YES;
    [self.window close];
    [NSApp stopModal];
}

- (void)skipClicked:(NSButton *)sender {
    self.userAllowed = NO;
    self.finished = YES;
    [self.window close];
    [NSApp stopModal];
}

- (BOOL)windowShouldClose:(NSWindow *)sender {
    self.userAllowed = NO;
    self.finished = YES;
    [NSApp stopModal];
    return YES;
}

@end

// ── 状态等待窗 ──────────────────────────────────────────────
// 系统弹窗弹出期间显示的小型无边框窗口，含旋转进度指示器和提示文字。
@interface WifisecWaitingWindow : NSObject
@property (nonatomic, strong) NSWindow *window;
@property (nonatomic, strong) NSProgressIndicator *spinner;
@end

@implementation WifisecWaitingWindow

- (instancetype)init {
    self = [super init];
    if (self == nil) {
        return nil;
    }

    NSRect frame = NSMakeRect(0, 0, 300, 100);
    NSUInteger style = NSWindowStyleMaskBorderless;
    self.window = [[NSWindow alloc] initWithContentRect:frame
                                              styleMask:style
                                                backing:NSBackingStoreBuffered
                                                  defer:NO];
    [self.window center];
    [self.window setReleasedWhenClosed:NO];
    [self.window setOpaque:NO];
    [self.window setBackgroundColor:[NSColor colorWithWhite:0.97 alpha:0.95]];
    [self.window setHasShadow:YES];
    [self.window setLevel:NSFloatingWindowLevel];

    NSView *content = self.window.contentView;
    [content setWantsLayer:YES];
    [content.layer setBackgroundColor:[[NSColor colorWithWhite:0.97 alpha:0.95] CGColor]];
    [content.layer setCornerRadius:12.0];

    // 旋转进度指示器
    self.spinner = [[NSProgressIndicator alloc] initWithFrame:NSMakeRect(20, 35, 30, 30)];
    [self.spinner setStyle:NSProgressIndicatorSpinningStyle];
    [self.spinner setIndeterminate:YES];
    [self.spinner startAnimation:nil];
    [content addSubview:self.spinner];

    // 提示文字
    NSTextField *label = [[NSTextField alloc] initWithFrame:NSMakeRect(60, 38, 220, 24)];
    [label setStringValue:@"等待授权中…请在系统弹窗中选择"];
    [label setFont:[NSFont systemFontOfSize:13]];
    [label setTextColor:BrandCyanDeep()];
    [label setBezeled:NO];
    [label setDrawsBackground:NO];
    [label setEditable:NO];
    [label setSelectable:NO];
    [content addSubview:label];

    return self;
}

- (void)show {
    [self.window orderFrontRegardless];
}

- (void)close {
    [self.spinner stopAnimation:nil];
    [self.window close];
}

@end

// ── CoreLocation Delegate ───────────────────────────────────

// WifisecLocationDelegate 在授权状态脱离"未决定"时结束 RunLoop 等待。
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

// ── C ABI ──────────────────────────────────────────────────

// wifisec_location_status 返回当前进程的定位授权状态；
// 系统定位总开关关闭时按 restricted 处理。
int wifisec_location_status(void) {
    if (![CLLocationManager locationServicesEnabled]) {
        return 1;
    }

    return (int)[[CLLocationManager alloc] init].authorizationStatus;
}

// wifisec_location_request 在状态为"未决定"时触发系统授权弹窗，
// 并运转 RunLoop 最多 timeout_sec 秒等待用户选择；状态已确定时直接返回，不弹窗。
//
// 首次授权（NotDetermined）时的完整流程：
//   1. 弹出品牌预提示窗（NSWindow modal），用户选「允许」或「跳过」
//   2. 用户选「允许」→ 关闭预提示窗，弹出状态等待窗，触发系统 TCC 弹窗
//   3. RunLoop 等待授权状态变化（delegate 回调 + 0.2s 轮询双保险）
//   4. 授权完成或超时 → 关闭状态等待窗，返回授权状态
//   用户选「跳过」→ 直接返回 NotDetermined，不触发系统弹窗
int wifisec_location_request(int timeout_sec) {
    if (timeout_sec < 1) {
        timeout_sec = 1;
    }

    // 无窗口 CLI 进程必须显式完成 NSApplication 启动并置为 Accessory，
    // 否则 LaunchServices 视其为"启动中"，TCC 授权弹窗被系统抑制，
    // 授权回调永远等不到用户输入，进程只能挂起到超时。
    NSApplication *application = [NSApplication sharedApplication];
    [application setActivationPolicy:NSApplicationActivationPolicyAccessory];
    [application finishLaunching];

    CLLocationManager *manager = [[CLLocationManager alloc] init];
    if (manager.authorizationStatus != kCLAuthorizationStatusNotDetermined) {
        return (int)manager.authorizationStatus;
    }

    // ── 步骤 1：品牌预提示窗 ──
    WifisecPrePromptController *promptController = [[WifisecPrePromptController alloc] init];
    [application runModalForWindow:promptController.window];

    if (!promptController.userAllowed) {
        // 用户点了「跳过」或关闭了窗口
        return (int)kCLAuthorizationStatusNotDetermined;
    }

    // ── 步骤 2：状态等待窗 + 系统弹窗 ──
    WifisecWaitingWindow *waiting = [[WifisecWaitingWindow alloc] init];
    [waiting show];

    WifisecLocationDelegate *delegate = [[WifisecLocationDelegate alloc] init];
    manager.delegate = delegate;
    [manager startUpdatingLocation];
    [manager requestAlwaysAuthorization];

    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:timeout_sec];
    NSDate *step = nil;

    // delegate 回调只是加速器：无 App 事件循环时它不一定被投递，
    // 因此每 0.2s 轮询一次状态，保证用户点完"允许"后循环必然退出。
    while (!delegate.finished && manager.authorizationStatus == kCLAuthorizationStatusNotDetermined) {
        step = [NSDate dateWithTimeIntervalSinceNow:0.2];
        if ([step compare:deadline] == NSOrderedDescending) {
            break;
        }
        [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:step];
    }

    // ── 步骤 3：关闭等待窗，返回状态 ──
    [waiting close];

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
