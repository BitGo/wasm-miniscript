WASM_PACK = wasm-pack
WASM_PACK_FLAGS = --no-pack --weak-refs

ifdef WASM_PACK_DEV
	WASM_PACK_FLAGS += --dev
endif

define WASM_PACK_COMMAND
	$(WASM_PACK) build --out-dir $(1) $(WASM_PACK_FLAGS) --target $(2)
endef

define REMOVE_GITIGNORE
	find $(1) -name .gitignore -delete
endef

define SHOW_WASM_SIZE
	@find $(1) -name "*.wasm" -exec gzip -k {} \;
	@find $(1) -name "*.wasm" -exec du -h {} \;
	@find $(1) -name "*.wasm.gz" -exec du -h {} \;
endef

define BUILD
	rm -rf $(1)
	$(call WASM_PACK_COMMAND,$(1),$(2))
	$(call REMOVE_GITIGNORE,$(1))
	$(call SHOW_WASM_SIZE,$(1))
endef

.PHONY: js/wasm/
js/wasm/:
	$(call BUILD,$@,nodejs)

.PHONY: dist/node/js/wasm/
dist/node/js/wasm/:
	$(call BUILD,$@,nodejs)

.PHONY: dist/browser/js/wasm/
dist/browser/js/wasm/:
	$(call BUILD,$@,browser)