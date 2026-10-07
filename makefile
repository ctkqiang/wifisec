.PHONY: run build clean tidy format test list help

MAIN_PATH := cmd/main.go
BUILD_PATH := build
APP_NAME := wifisec

run:
	@echo "正在运行应用..."
	go run -race $(MAIN_PATH)

build:
	@echo "正在编译二进制文件..."
ifeq ($(shell uname -s),Darwin)
# macOS 发布物必须是 .app bundle：定位授权（TCC）弹窗只对 LaunchServices
# 激活的 bundle 呈现，终端里直接执行的裸二进制责任进程归属终端宿主，
# 宿主未声明定位用途时系统会静默丢弃授权请求。
# 另建同名符号链接，保留 ./build/wifisec list 的 CLI 使用习惯。
	@rm -rf $(BUILD_PATH)/$(APP_NAME) $(BUILD_PATH)/$(APP_NAME).app
	@mkdir -p $(BUILD_PATH)/$(APP_NAME).app/Contents/MacOS
	@go build -o $(BUILD_PATH)/$(APP_NAME).app/Contents/MacOS/$(APP_NAME) $(MAIN_PATH)
	@cp internal/platform/darwin/Info.plist $(BUILD_PATH)/$(APP_NAME).app/Contents/Info.plist
	@codesign --sign - --force $(BUILD_PATH)/$(APP_NAME).app \
		&& echo "已完成 macOS ad-hoc 签名（首次运行的定位授权弹窗依赖此签名）" \
		|| echo "警告：codesign 失败，请确认已安装 Xcode Command Line Tools；未签名时 BSSID 授权弹窗可能无法弹出"
	@ln -s $(APP_NAME).app/Contents/MacOS/$(APP_NAME) $(BUILD_PATH)/$(APP_NAME)
else
	@go build -o $(BUILD_PATH)/$(APP_NAME) $(MAIN_PATH)
endif

clean:
	@echo "正在清理编译产物..."
	rm -rf $(BUILD_PATH)/$(APP_NAME) $(BUILD_PATH)/$(APP_NAME).app

tidy:
	go mod tidy

format:
	@echo "正在格式化代码..."
	go fmt ./...

test:
	@echo "正在运行测试..."
	go test ./...

list:
	@echo "正在列出WiFi网络..."
	go run -race $(MAIN_PATH) list $(TARGET)

help:
	@echo "正在显示帮助信息..."
	go run -race $(MAIN_PATH) help