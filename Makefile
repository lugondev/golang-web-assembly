all: build

build:
	GOOS=js GOARCH=wasm go build -o  assets/json.wasm
