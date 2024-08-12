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

define BUILD
	$(call WASM_PACK_COMMAND,$(1),$(2))
	$(call REMOVE_GITIGNORE,$(1))
endef

.PHONY: js/wasm/
js/wasm/:
	$(call BUILD,$@,nodejs)

.PHONY: dist/wasm/
dist/wasm/:
	$(call BUILD,$@,nodejs)

.PHONY: dist/browser/wasm/
dist/browser/wasm/:
	$(call BUILD,$@,browser)