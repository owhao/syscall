TARGET_MODULE	:=syscall

SRCDIR      	:= src
SFILES      	:= sample.c syscall.c
IFILES      	:= syscall.h

OBJFILES   		:= $(patsubst %,$(SRCDIR)/%,$(SFILES))
INCFILES   		:= $(patsubst %,$(SRCDIR)/%,$(IFILES))

# If we are running by kernel building system
ifneq ($(KERNELRELEASE),)
	$(TARGET_MODULE)-objs := $(OBJFILES:.c=.o)
	obj-m := $(TARGET_MODULE).o

# If we running without kernel build system
else
	BUILDSYSTEM_DIR:=/lib/modules/$(shell uname -r)/build
	PWD:=$(shell pwd)

all: $(TARGET_MODULE)

$(TARGET_MODULE):
# run kernel build system to make modulel
	$(MAKE) -C $(BUILDSYSTEM_DIR) M=$(PWD) modules

clean:
# run kernel build system to cleanup in current directory
	$(MAKE) -C $(BUILDSYSTEM_DIR) M=$(PWD) clean

load:
	insmod ./$(TARGET_MODULE).ko

unload:
	rmmod $(TARGET_MODULE)

endif