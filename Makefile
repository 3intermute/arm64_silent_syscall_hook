obj-m += ehh.o
ehh-objs = resolve_kallsyms.o set_page_flags.o assembler.o hook.o copy_sys_call_table.o ehh_init.o
# _CFLAGS += -fPIE -fPIC
# ccflags-y += ${_CFLAGS}
# CC += ${_CFLAGS}

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	# EXTRA_CFLAGS="$(_CFLAGS)"

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
