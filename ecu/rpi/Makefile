
LIBS =

INCLUDES = -I../../include/ -I../../enclave/lib/include/

all: ecu

ecu: main.o
		 gcc -o ecu $(LIBS) main.o

main.o: main.c
		 gcc -c main.c $(INCLUDES)
		      
clean:
		 rm main.o ecu
