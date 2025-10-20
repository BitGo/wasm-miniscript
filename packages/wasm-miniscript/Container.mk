.PHONY: all build-image build-wasm enter-image clean-container clean-image

CONTAINER_ENGINE ?= docker

all: build-image build-wasm

build-image:
	$(CONTAINER_ENGINE) build --tag wasm-builder .

build-wasm:
	rm -rf dist/ js/wasm/
	$(CONTAINER_ENGINE) rm -f wasm-builder-container || true
	$(CONTAINER_ENGINE) run -v $(shell pwd)/src:/usr/src/app/src \
	--name wasm-builder-container wasm-builder \
	npm run build
	$(CONTAINER_ENGINE) cp wasm-builder-container:/usr/src/app/dist .
	$(CONTAINER_ENGINE) cp wasm-builder-container:/usr/src/app/js/wasm ./js/wasm

enter-image:
	$(CONTAINER_ENGINE) run -it wasm-builder /bin/bash

clean-container:
	$(CONTAINER_ENGINE) rm wasm-builder-container

clean-image:
	$(CONTAINER_ENGINE) rmi wasm-builder
