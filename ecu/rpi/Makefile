
LIBS =

all: ecu

ecu: main.o
		 gcc -o ecu $(LIBS) main.o

main.o: main.c
		 gcc -c main.c
		      
clean:
		 rm main.o ecu
