27-SEPT-JULY-2017 Matthew J. Wolf <matthew.wolf.hpsdr@speciosus.net>

The N4MTT FTDI-usbswitch is an example Linux program of how to use the libFTDI with an 
FTDI UART (USB to RS232) interface in bit bang mode. I use the program to toggle things on and off.

I use the lowest bit with the NOT gate to toggle power to a pair of 
studio audio monitors. The NOT gate is connect to a switch that I built 
that is similar to a "Power Switch Tail".

The higher bit is used to toggle power a sigma delta audio DAC. The pin is 
connected to a Digital Loggers Iot Power Relay",
https://dlidirect.com/products/iot-power-relay.

The program is written to run with Linux 

Known issue: The first command after the program is started has
to be placed into the FIFO two times. All the following commands work
as expected. I am going to try to resolve this issue in the next version
of the program.

The program has to modes of operatson.

When the program is stared with no arguments it detaches from the
from the terminal and runs as a daemon.

The second mode of operation is debug mode. When the program
is started with the argument of "-d", the program does not detach
from the terminal. In debug mode the commands that are placed in 
the FIFO cause messages to get printed on the terminal.

The user who is running the program needs to have full access to the USB
device.  

      
FTDI USB Switch
---------------
A daemon that watches a FIFO for a single letter.
The letter determines what happens to the state of the pins 
on FTDI USB UART in bit bang mode. A USB UART is more commonly known as  
as a USB to RS232 interface.   

- The logic on the lowest pin is reversed. The pin is connected to a 
   NPN transistor NOT gate.
   The FTDI pin set low (0) causes the output of the NOT gate high (1).
   The FTDI pin set high (1) causes the output of the NOT gate low (0). 

- The logic on the next highest pin is not connected to a NOT gate.
   The FTDI pin set low (0) causes the output of the pin logic low (0).
   The FTDI pin set high (1) causes the output of the pin logic high (1). 
 
 Letter sent to the FIFO and the daemons' action:
 "A" - ALL ON  > Turn both pins on,
 "a" - ALL OFF > Turn both pins off.
 "p" - POWER   > LOW BIT / PIN:
               (current pins state) & 0xFE
               (current pins state) (bit wise add) 0xFE
               The ADD is used to clear the last bit low. 
 "o" - OFF     > LOW BIT / PIN:
               (current pins state) | 0x01
               (current pins state) (bit wise or) 0x01
               The OR is used to set the last bit high.
 "P" - POWER   > NEXT HIGHER BIT / PIN:
               (current pins state) | 0x02
               (current pins state) (bit wise or) 0x02
               The OR is used to set the next higher bit low.
 "O" - OFF     > NEXT HIGHER BIT / PIN: 
               (current pins state) & 0xFD
               (current pins state) (bit wise and) 0xFD
               The AND is used to set the next higher bit high.
 "x" - EXIT    >
               The daemon stops running.
               In debug mode the program stops running.

 Debug Mode
 ----------
 Starting the program with the argument of "-d"
 causes the program of not daemonize. Additionally
 debug messages are displayed on standard out (stdout).

 Required Libraries
 ------------------
 Core C library
 libusb-1.0 (Required for libFTDI) 
 libFTDI  
 - System package or https://www.intra2net.com/en/developer/libftdi/index.php 
 - I tested with libFTDI versions 1.2, 1.3, and 1.4 
 - libFTDI works with FT232BM, FT245BM, FT2232C, FT2232D, FT245R,
   FT232H and FT230X FTDI chips. 
