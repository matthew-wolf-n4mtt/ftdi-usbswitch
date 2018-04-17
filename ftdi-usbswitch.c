/* ftdi-usbswitch.c - Program to toggle bits on a FTDI USB UART in Bit Bang Mode
 * Version: 3.0
 * Author:  Matthew J. Wolf
 * Date:    31 MAR 2018
 *
 * Changes: 2.0 - Added 2nd bit / pin
 *          2.1 - Using select and file descriptor to wait for FIFO I/O.
 *          2.2 - Added "ALL" commands and removed the need to read the current
 *                sate of the bits from the FTDI interface.
 *          3.0 - Changed source file name. Added better daemonize logic and
 *                system logging.
 *
 * This file is part of the N4MTT FTDI-usbswitch.
 * By Matthew J. Wolf <matthew.wolf.hpsdr@speciosus.net>
 * Copyright 2018 Matthew J. Wolf
 *
 * The N4MTT FTDI-usbswitch is free software: you can
 * redistribute it and/or modify it under the terms of the GNU
 * General Public License as published by the Free Software Foundation,
 * either version 2 of the License, or (at your option) any later version.
 *
 * The  N4MTT FTDI-usbswitch is distributed in the hope that
 * it will be useful, but WITHOUT ANY WARRANTY; without even the implied
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
 * the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with the HPSDR-USB Plug-in for Wireshark.
 * If not, see <http://www.gnu.org/licenses/>.
 *
 * FTDI USB Switch
 * ---------------
 * A daemon that watches a FIFO for a single letter.
 * The letter determines what happens to the state of the pins
 * on FTDI USB UART in bit bang mode. A USB UART is more commonly known as
 * as a USB to RS232 interface.
 *
 * - The logic on the lowest pin is reversed. The pin is connected to a
 *   NPN transistor NOT gate.
 *   The FTDI pin set low (0) causes the output of the NOT gate high (1).
 *   The FTDI pin set high (1) causes the output of the NOT gate low (0).
 *
 * - The logic on the next highest pin is not connected to a NOT gate.
 *   The FTDI pin set low (0) causes the output of the pin logic low (0).
 *   The FTDI pin set high (1) causes the output of the pin logic high (1).
 *
 * Letter sent to the FIFO and the daemons' action:
 * "A" - ALL ON  > Turn both pins on,
 * "a" - ALL OFF > Turn both pins off.
 * "p" - POWER   > LOW BIT / PIN:
 *               (current pins state) & 0xFE
 *               (current pins state) (bit wise add) 0xFE
 *               The ADD is used to clear the last bit low.
 * "o" - OFF     > LOW BIT / PIN:
 *               (current pins state) | 0x01
 *               (current pins state) (bit wise or) 0x01
 *               The OR is used to set the last bit high.
 * "P" - POWER   > NEXT HIGHER BIT / PIN:
 *               (current pins state) | 0x02
 *               (current pins state) (bit wise or) 0x02
 *               The OR is used to set the next higher bit low.
 * "O" - OFF     > NEXT HIGHER BIT / PIN:
 *               (current pins state) & 0xFD
 *               (current pins state) (bit wise and) 0xFD
 *               The AND is used to set the next higher bit high.
 * "x" - EXIT    >
 *               The daemon stops running.
 *               In debug mode the program stops running.
 *
 * FT232RL
 * -------
 * Bit	Pin
 *  0    1   Lowest Bit - Commands: p and o
 *  1    5   Higher Bit - Commands: P and O
 *  2    3
 *  3    11
 *  4    2
 *  5    9
 *  6    10
 *  7    6
 *
 * Debug Mode
 * ----------
 * Starting the program with the argument of "-d"
 * causes the program of not daemonize. Additionally
 * debug messages are displayed on standard out (stdout).
 * Debug mode has not been fully tested.
 *
 * Required Libraries
 * ------------------
 * Core C library
 * libusb-1.0 (Required for libFTDI)
 * libFTDI
 * - System package or https://www.intra2net.com/en/developer/libftdi/index.php
 * - I tested with libFTDI versions 1.2, 1.3, and 1.4
 * - libFTDI works with FT232BM, FT245BM, FT2232C, FT2232D, FT245R,
 *   FT232H and FT230X FTDI chips.
 */
//345678911234567892123456789312345678941234567895123456789612345678971234567898
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <libftdi1/ftdi.h>
#include <sys/stat.h>
#include <sys/resource.h>

void set_pin_state(struct ftdi_context *ftdi, int state);
int exit_stop (struct ftdi_context *ftdi, char *fifo);
void signal_handler(int signal);
void daemonize();

#define LOCKFILE "/var/run/ftdi-usbswitch.pid"
#define FIFOFILE "/tmp/ftdi-usbswitch"

pid_t pid, sid;
FILE *pidfile;

int debug = 0;

// Global for the sin handler
struct ftdi_context *ftdi;

int main(int argc, char ** argv) {

        int i = -1;
        int rc = -1;
        int ret_value = -1;
        int fifo_command = -1;
        int reg_track = -1;

        char fifo_buf[5];
        unsigned char buf[1];

        fd_set fd_fifo_read;

        for ( i=1; i < argc; i++ ) {
                if (!strcmp("-d",argv[i])) {
                        debug = 1;
                }

        }

        openlog("ftdi-usbswitch",LOG_PID, LOG_DAEMON);

        unlink(FIFOFILE); // remove old fifo

        umask(000);
        ret_value = mkfifo(FIFOFILE,
                           S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH
                           | S_IWOTH);
        if (ret_value < 0) {
                if (debug) {
                        fprintf(stderr,"FIFO Create Error %s: %s\n",FIFOFILE,
                                strerror(errno));
                }
                syslog(LOG_ERR,"FIFO Create Error %s: %s",FIFOFILE,
                       strerror(errno));
                exit (EXIT_FAILURE);
        }

        // Open FIFO and initialize the file descriptor set
        fifo_command = open (FIFOFILE, O_RDWR | O_NONBLOCK);
        FD_ZERO(&fd_fifo_read);
        FD_SET(fifo_command,&fd_fifo_read);

        // Fork Daemon
        if (!debug) {
                daemonize();
        }

        if ((ftdi = ftdi_new()) == 0) {
                if (debug) {
                        fprintf(stderr, "ftdi_new failed: %s\n",
                                strerror(errno));
                }
                syslog(LOG_ERR,"ftdi_new failed: %s",strerror(errno));
                exit(EXIT_FAILURE);
        }

        // Open FTDI device at default address
        ret_value = ftdi_usb_open(ftdi, 0x0403, 0x6001);

        if (ret_value < 0 && ret_value != -5) {
                if (debug) {
                        fprintf(stderr,"Unable to open ftdi device: %d (%s)\n",
                                ret_value, ftdi_get_error_string(ftdi));
                }
                syslog(LOG_ERR,"Unable to open ftdi device: %d (%s)",
                       ret_value, ftdi_get_error_string(ftdi));
                ftdi_free(ftdi);
                exit(EXIT_FAILURE);
        }

        // Enable Bit Bang Mode
        ftdi_set_bitmode(ftdi, 0xFF, BITMODE_BITBANG);

        // When the ftdi is plugged to USB port all pins are logic high.

        // Set lowest bit / pin high - off
        // Set next higher bit / pin low - off.
        buf[0] = 0xFD;
        reg_track = buf[0];
        ret_value = ftdi_write_data(ftdi, buf, 1);
        if (ret_value < 0) {
                if (debug) {
                        fprintf(stderr,"Write failed for 0x%x, error %d (%s)\n",
                                buf[0],ret_value, ftdi_get_error_string(ftdi));
                }
                syslog(LOG_ERR,"Write failed for 0x%x, error %d (%s)",
                       buf[0],ret_value, ftdi_get_error_string(ftdi));
        }

        for (;; ) {

                rc = select(fifo_command+1,&fd_fifo_read, NULL, NULL, NULL);

                if ( rc == 0 ) { // Select Timeout
                        continue;
                } else if ( rc == -1 ) {
                        if (debug) {
                                fprintf(stderr,"Select Error: %s\n",
                                        strerror(errno));
                        }
                        syslog(LOG_ERR,"Select Error: %s",strerror(errno));
                }

                if (FD_ISSET(fifo_command,&fd_fifo_read)) {

                        // Read FIFO to see if there is a command in the FIFO
                        // buffer.
                        read(fifo_command,fifo_buf,1);

                        if (strcmp("A",fifo_buf) == 0) {
                                if (debug) { printf("FIFO Command ALL ON\n"); }

                                reg_track = 0xFE;
                                set_pin_state(ftdi,reg_track);

                        } else if (strcmp("a",fifo_buf) == 0) {
                                if (debug) { printf("FIFO Command ALL OFF\n"); }

                                reg_track = 0xFD;
                                set_pin_state(ftdi,reg_track);


                                // Power (ON) - Lowest Bit
                        } else if (strcmp("p",fifo_buf) == 0) {
                                if (debug) {
                                        printf("FIFO Command POWER -> "
                                               "Lowest Bit / Pin\n");
                                }

                                // Logic is reversed.
                                // AND to clear the lowest bit.
                                // Then update pins register.
                                reg_track &= 0xFE;
                                buf[0] = reg_track;
                                set_pin_state(ftdi,reg_track);

                                // OFF - Lowest Bit
                        } else if (strcmp("o",fifo_buf) == 0) {
                                if (debug) {
                                        printf("FIFO Command OFF   -> "
                                               "Lowest Bit / Pin\n");
                                }

                                // Logic is reversed.
                                // OR to set the lowest bit.
                                // Then update pins register.
                                reg_track |= 0x01;
                                buf[0] = reg_track;
                                set_pin_state(ftdi,reg_track);

                                // Power (ON) - Higher Bit
                        } else if (strcmp("P",fifo_buf) == 0) {
                                if (debug) {
                                        printf("FIFO Command POWER -> "
                                               "Higher Bit / Pin\n");
                                }

                                // OR to set the next higher bit.
                                // Then update pins register.
                                reg_track |= 0x02;
                                buf[0] = reg_track;
                                set_pin_state(ftdi,reg_track);

                                // OFF - Higher Bit
                        } else if (strcmp("O",fifo_buf) == 0) {
                                if (debug) {
                                        printf("FIFO Command OFF   -> "
                                               "Higher Bit / Pin\n");
                                }

                                // AND to set the the next higher bit.
                                // Then update pins register.
                                reg_track &= 0xFD;
                                buf[0] = reg_track;
                                set_pin_state(ftdi,reg_track);

                                // Exit or Stop
                        } else if (strcmp("x",fifo_buf) == 0) {
                                if (debug) { printf("FIFO Command EXIT\n"); };

                                if ( exit_stop(ftdi,FIFOFILE) == EXIT_SUCCESS )
                                {
                                        exit(EXIT_SUCCESS);
                                } else {
                                        exit(EXIT_FAILURE);
                                }

                        }

                }

                // Clear buf
                memset(fifo_buf,0, sizeof(fifo_buf) );

        }

        if ( exit_stop(ftdi,FIFOFILE) == EXIT_SUCCESS ) {
                exit(EXIT_SUCCESS);
        } else {
                exit(EXIT_FAILURE);
        }

}

void set_pin_state(struct ftdi_context *ftdi, int state) {

        int rc =-1;
        unsigned char buf[1];

        buf[0] = state;
        rc = ftdi_write_data(ftdi, buf, 1);
        if (rc < 0) {
                if (debug) {
                        fprintf(stderr,"Write failed for 0x%x, error %d (%s)\n",
                                buf[0],rc, ftdi_get_error_string(ftdi));
                }
                syslog(LOG_ERR,"Write failed for 0x%x, error %d (%s)",
                       buf[0],rc, ftdi_get_error_string(ftdi));
        }

}

int exit_stop (struct ftdi_context *ftdi, char *fifo) {

        int rc = -1;

        ftdi_disable_bitbang(ftdi);

        if ((rc = ftdi_usb_close(ftdi)) < 0) {
                if (debug) {
                        fprintf(stderr, "Unable to close ftdi device: %d (%s)\n",
                                rc, ftdi_get_error_string(ftdi));
                }
                syslog(LOG_ERR,"Unable to close ftdi device: %d (%s)",
                       rc, ftdi_get_error_string(ftdi));
                ftdi_free(ftdi);
                return EXIT_FAILURE;
        }

        ftdi_free(ftdi);

        // Remove FIFO
        unlink(fifo);

        return EXIT_SUCCESS;
}

void signal_handler(int signal) {

        switch (signal) {
        case SIGTERM:
                syslog(LOG_NOTICE,"Received SIGTERM: Exiting");
                exit_stop(ftdi,FIFOFILE);
                unlink(LOCKFILE);
                exit(EXIT_SUCCESS);
                break;
        case SIGINT:
                syslog(LOG_NOTICE,"Received SIGINT: Exiting");
                exit_stop(ftdi,FIFOFILE);
                unlink(LOCKFILE);
                exit(EXIT_SUCCESS);
                break;
        case SIGKILL:
                syslog(LOG_NOTICE,"Received SIGKILL: Exiting");
                exit_stop(ftdi,FIFOFILE);
                unlink(LOCKFILE);
                exit(EXIT_SUCCESS);
                break;
        }

}

void daemonize() {
        int lf_fd;
        char buf[16];
        pid_t pid, sid;

        struct flock lf_flock;
        struct rlimit rl;
        struct sigaction sa;

        // Change the file mode mask
        umask(0);

        // Get the max limit of file descriptors
        if( getrlimit(RLIMIT_NOFILE, &rl) < 0 ) {
                syslog(LOG_ERR,"Can get file limit: %s",strerror(errno));
                exit(EXIT_FAILURE);
        }

        // Add comment
        if ( (pid = fork()) < 0 ) {
                syslog(LOG_ERR,"Unable to create child process: %s",
                       strerror(errno));
                exit(EXIT_FAILURE);
        }

        if (pid > 0) {  // Parent Exit
                exit(EXIT_SUCCESS);
        }

        // Get new session ID for child process.
        // Become session lead to drop controlling TTY.
        if ( (sid = setsid()) < 0 ) {
                syslog(LOG_ERR,"Child session ID error: %s",strerror(errno));
                exit(EXIT_FAILURE);
        }

        // Chnage working directory to root. This do that the daemon process
        // will not be able to make and file system changes or unmount any file
        // system.
        if (chdir("/") < 0 ) {
                syslog(LOG_ERR,"Can change working directory to /: %s",
                       strerror(errno));
                exit(EXIT_FAILURE);
        }

        // Setup signal handler with system kernel.
        // Clear the signal mask so that no new TTYs will be opened.
        sa.sa_handler = signal_handler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;
        sigaction(SIGTERM,&sa,NULL);
        sigaction(SIGINT,&sa,NULL);
        sigaction(SIGKILL,&sa,NULL);

        // Create lock / pid file.
        lf_fd = open(LOCKFILE, O_RDWR | O_CREAT,
                     S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
        if (lf_fd < 0) {
                syslog(LOG_ERR,"Can not open lock file %s: %s",LOCKFILE,
                       strerror(errno));
                exit(EXIT_FAILURE);
        }

        // // Lock the lock / pid file
        lf_flock.l_type = F_WRLCK;
        lf_flock.l_start = 0;
        lf_flock.l_whence = SEEK_SET;
        lf_flock.l_len = 0;

        if ( fcntl(lf_fd, F_SETLK, &lf_flock) < 0 ) {
                if (errno == EACCES || errno == EAGAIN) {
                        syslog(LOG_ERR,"Lock file access issue %s: %s",
                               LOCKFILE,strerror(errno));
                        close(lf_fd);
                        exit(EXIT_FAILURE);
                }
                syslog(LOG_ERR,"Can not lock %s: %s",LOCKFILE,strerror(errno));
                close(lf_fd);
                exit(EXIT_FAILURE);
        }

        // Add comment
        ftruncate(lf_fd,0);
        sprintf(buf,"%ld", (long)getpid());
        write(lf_fd,buf,strlen(buf)+1);

        // Close out the standard file descriptors
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);

        syslog(LOG_NOTICE,"Start Up");

        return;
}
