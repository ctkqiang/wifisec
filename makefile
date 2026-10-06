.PHONY: run build clean tidy format test list help

MAIN_PATH := cmd/main.go
APP_NAME := wifisec

run:
	@echo "正在运行应用..."
	go run -race $(MAIN_PATH)

build:
	@echo "正在编译二进制文件..."
	go build -o build/$(APP_NAME) $(MAIN_PATH)

clean:
	@echo "正在清理编译产物..."
	rm -rf bin/

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