obj-m += xt_novrf.o
XT_CFLAGS = -Wall -Wextra -pedantic -O2

all: kernel-module iptables-module

kernel-module:
	make -C /lib/modules/$(shell uname -r)/build M=$(CURDIR) modules

iptables-module: libxt_novrf.so

libxt_novrf.so: libxt_novrf.o
	gcc -shared -fPIC ${XT_CFLAGS} -o $@ $^;

libxt_novrf.o: libxt_novrf.c
	gcc ${XT_CFLAGS} -D_INIT=lib$*_init -fPIC -c -o $@ $<;

clean: clean-kernel-module clean-iptables-module

clean-kernel-module:
	make -C /lib/modules/$(shell uname -r)/build M=$(CURDIR) clean

clean-iptables-module:
	rm -f libxt_novrf.o libxt_novrf.so
