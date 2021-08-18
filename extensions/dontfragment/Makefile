obj-m += ipt_DF.o
IPT_CFLAGS = -Wall -Wextra -pedantic -O2

all: kernel-module iptables-module

kernel-module:
	make -C /lib/modules/$(shell uname -r)/build M=$(CURDIR) modules

iptables-module: libipt_DF.so

libipt_DF.so: libipt_DF.o
	gcc -shared -fPIC ${IPT_CFLAGS} -o $@ $^;

libipt_DF.o: libipt_DF.c
	gcc ${IPT_CFLAGS} -D_INIT=lib$*_init -fPIC -c -o $@ $<;

clean: clean-kernel-module clean-iptables-module

clean-kernel-module:
	make -C /lib/modules/$(shell uname -r)/build M=$(CURDIR) clean

clean-iptables-module:
	rm -f libipt_DF.o libipt_DF.so
