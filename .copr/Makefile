top:=$(abspath $(dir $(lastword $(MAKEFILE_LIST)))..)

prereq:
	rpm -q git rpm-build > /dev/null || dnf -y install git rpm-build

srpm: prereq
	$(MAKE) -C $(top) srpm
