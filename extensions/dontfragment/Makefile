obj-m += ipt_DF.o
#IPT_CFLAGS = -fPIC -Wall -Wextra -pedantic
IPT_CFLAGS = -fPIC
IPTABLES_VERSION = 1.6.2

all: kernel-module iptables-module

iptables: iptables-$(IPTABLES_VERSION) ipt_DF.h
	cp ipt_DF.h iptables-$(IPTABLES_VERSION)/include/linux/netfilter_ipv4/ipt_DF.h

iptables-$(IPTABLES_VERSION): iptables-$(IPTABLES_VERSION).tar.bz2
	tar -xf iptables-$(IPTABLES_VERSION).tar.bz2

iptables-$(IPTABLES_VERSION).tar.bz2:
	wget http://www.netfilter.org/projects/iptables/files/iptables-$(IPTABLES_VERSION).tar.bz2
	md5sum -c iptables-$(IPTABLES_VERSION).tar.bz2.md5 || (rm -f iptables-$(IPTABLES_VERSION).tar.bz2 && exit 1)

kernel-module:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

iptables-module: iptables libipt_DF.c
	$(CC) $(CFLAGS) $(IPT_CFLAGS) -I iptables-$(IPTABLES_VERSION)/include libipt_DF.c -c
	$(CC) $(CFLAGS) $(IPT_CFLAGS) -shared -o libipt_DF.so libipt_DF.o

clean-all: clean clean-iptables-archive

clean: clean-kernel-module clean-iptables-module clean-iptables

clean-kernel-module:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

clean-iptables-module:
	rm -f libipt_DF.o libipt_DF.so

clean-iptables:
	rm -rf iptables-$(IPTABLES_VERSION)

clean-iptables-archive:
	rm -f iptables-$(IPTABLES_VERSION).tar.bz2
