DEMO_LIST ?= $(shell find . -mindepth 1 -type d)
DEMO_LIST_EXCEPT_INSTALL ?= $(shell find . -mindepth 1 -type d | grep -v install)

aggpath := $(shell command -v agg 2>/dev/null || true)
ifeq ($(aggpath),)
        $(error Please install agg: https://github.com/asciinema/agg)
endif

all: $(addsuffix /demo.gif,$(DEMO_LIST))

all-gadgets: $(addsuffix /demo.gif,$(DEMO_LIST_EXCEPT_INSTALL))

%/demo.gif: %/*.sh check-terminal
	@echo "Demo $*"
	rm -f $*/demo.cast $*/demo.gif
	@echo "Demo $*: initialization"
	[ ! -x "$*/init.sh" ] || $*/init.sh
	DEMO_AUTO_RUN=1 TERM=xterm time asciinema rec -c $*/demo.sh $*/demo.cast
	@echo "Demo $*: finalization"
	[ ! -x "$*/fini.sh" ] || $*/fini.sh
	cat $*/demo.cast
	@echo "Demo $*: converting cast file to gif"
	agg $*/demo.cast $*/demo.gif
	ls -lh $*/demo.gif

.PHONY: check-terminal
check-terminal:
	echo -ne '\e[8;24;80t'
	test `tput lines` -eq 24
	test `tput cols` -eq 80

.PHONY: list
list:
	@echo $(DEMO_LIST)

.PHONY: list-gadgets
list-gadgets:
	@echo $(DEMO_LIST_EXCEPT_INSTALL)

.PHONY: install
install:
	for i in $(DEMO_LIST) ; do \
		if [[ ! "$$i" =~ "install" ]] ; then \
			cp $${i}/demo.gif ../../docs/guides/$${i/-//}.gif ; \
			echo "Installing docs/guides/$${i/-//}.gif"; \
		fi ; \
	done
	cp install/demo.gif ../../docs/install.gif
	echo "Installing docs/install.gif"

clean:
	rm -f */*.cast */*.gif
