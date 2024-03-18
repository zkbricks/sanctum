TARGET=../../target

default: build

all: test

test: build
	cargo test

build:
	soroban contract build
	@ls -l $(TARGET)/wasm32-unknown-unknown/release/*.wasm

fmt:
	cargo fmt --all

clean:
	cargo clean
