CONFIG_MODULE_SIG=n

KERN_DIR = /lib/modules/$(shell uname -r)/build
myfw-objs := myfw_mod.o #file2.o file3.o
obj-m += myfw.o

all:
	make -C $(KERN_DIR) M=$(shell pwd) modules 
	g++ -o myfw ../client/src/Connection.cpp ../client/src/Log.cpp ../client/src/myFirewall.cpp ../client/src/Rule.cpp ../client/src/Util.cpp  
clean:                                  
	make -C $(KERN_DIR) M=$(shell pwd) modules clean
	rm -rf modules.order
	rm -f *.symvers
	rm -f myfw