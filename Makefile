CFLAGS = -Wall

all: ftdi-usbswitch

ftdi-usbswitch: usbswitch.o
	$(CC) -Wall usbswitch.o -o ftdi-usbswitch -lftdi1

clean:
	rm -f *.o ftdi-usbswitch

%.0:	%.c
	$(CC) -c $< -o $@ 
