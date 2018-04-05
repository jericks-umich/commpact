
LIBS = -lcrypto

INCLUDES = -I../../include/ -I../../enclave/lib/include/

all: ecu

ecu: main.o cp_crypto.o
		 gcc -o ecu $(LIBS) main.o cp_crypto.o

main.o: main.c cp_crypto.h
		 gcc -c main.c $(INCLUDES)
		      
cp_crypto.o: cp_crypto.c cp_crypto.h
	gcc -c cp_crypto.c $(INCLUDES)

clean:
		 rm main.o cp_crypto.o ecu
