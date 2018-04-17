CFLAGS = -Wall

all: ftdi-usbswitch

ftdi-usbswitch: ftdi-usbswitch.o
	$(CC) -Wall ftdi-usbswitch.o -o ftdi-usbswitch -lftdi1

clean:
	rm -f *.o ftdi-usbswitch

%.0:	%.c
	$(CC) -c $< -o $@
