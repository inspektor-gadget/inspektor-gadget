KERNEL_VERSION ?= v6.2
URL ?= https://raw.githubusercontent.com/torvalds/linux/$(KERNEL_VERSION)/include/net/dropreason.h

# If a new release of Linux adds new entries in dropreason.h, you can use this
# to update the copy in Inspektor Gadget.
.PHONY: download
download:
	rm -f dropreason.h
	curl -f --output dropreason.h $(URL)
	(echo "// Downloaded from $(URL)" ; cat dropreason.h) | sponge dropreason.h
