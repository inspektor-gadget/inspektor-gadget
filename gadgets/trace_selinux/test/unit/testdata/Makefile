# policy.bin is committed so that the test does not need checkpolicy. Run
# "make" after changing policy.conf. The output of checkpolicy is reproducible.
#
# -U allow: allow every class and permission not declared in policy.conf.
# -c 33: highest policy version supported by Linux v5.10.

SUDO ?= sudo

policy.bin: policy.conf
	checkpolicy -U allow -c 33 -o $@ $<

.PHONY: install-tools
install-tools:
	$(SUDO) apt-get install -y checkpolicy
