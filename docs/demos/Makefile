SRC=$(wildcard *.txt)
DST=$(SRC:.txt=.gif)
all: $(DST)

%.gif: %.txt
	@# Uses gifterminal.sh from https://github.com/kinvolk/gifterminal/tree/kai/fonts-and-paths
	# Writing $@
	@if [ "$@" = demo-tcpconnect-gifterminal.gif ]; then \
	  BACKGROUND=backgroundkinvolk-logo-upper-right.gif gifterminal.sh $< $@ ; \
	else \
	  BACKGROUND=backgroundkinvolk-logo-upper-right-single.gif gifterminal.sh $< $@ ; \
	fi
	# Wrote $@
