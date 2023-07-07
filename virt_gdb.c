#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>

typedef uint64_t seL4_Word;
#define NUM_REGS 34
#define NUM_REGS64 (NUM_REGS - 1)

#define SOCK_NAME "/tmp/gdb-socket"
#define BUFSIZE 1024

#define DEBUG_PRINTS

/* Input buffer */
static char kgdb_in[BUFSIZE];

/* Output buffer */
static char kgdb_out[BUFSIZE];

/* Hex characters */
static char hexchars[] = "0123456789abcdef";

static int listen_socket;
static int data_socket;

/* Output a character to serial */
static void gdb_putChar(char c)
{
    write(data_socket, &c, 1);
}

// /* Read a character from serial */
static char gdb_getChar(void)
{
    char c; 
    read(data_socket, &c, 1);
    return c; 
}

typedef struct register_set {
    uint64_t registers_64[NUM_REGS - 1];
    uint32_t cpsr; 
} register_set_t;

register_set_t reg_state = {0};

/* Convert a character (representing a hexadecimal) to its integer equivalent */
static int hex (unsigned char c) {
	if (c >= 'a' && c <= 'f') {
		return c - 'a' + 10;
	} else if (c >= 'A' && c <= 'F') {
		return c - 'A' + 10;
	} else if (c >= '0' && c <= '9') {
		return c - '0';
	}
	return -1; 
}


static char *kgdb_get_packet(void) {
	char c;
	int count;
	/* Checksum and expected checksum */
	unsigned char cksum, xcksum;
	char *buf = kgdb_in;
	(void) buf;	

	while (1) {
		/* Wait for the start character - ignoring all other characters */
		while ((c = gdb_getChar()) != '$')
#ifndef DEBUG_PRINTS
			;
#else 
		{
			printf("%c", c);
		}
		printf("%c", c);
#endif 
retry:
		/* Initialize cksum variables */
		cksum = 0;
		xcksum = -1;
		count = 0;
		(void) xcksum;

		/* Read until we see a # or the buffer is full */
		while (count < BUFSIZE - 1) {
			c = gdb_getChar();
#ifdef DEBUG_PRINTS
		    printf("%c", c);
#endif
			if (c == '$') {
				goto retry;
			} else if (c == '#') {
				break;
			}
			cksum += c;
			buf[count++] = c;
		}

		/* Null terminate the string */
		buf[count] = 0;

#ifdef DEBUG_PRINTS
			printf("\nThe value of the command so far is %s. The checksum you should enter is %x\n", buf, cksum);
#endif

		if (c == '#') {
			c = gdb_getChar();
			xcksum = hex(c) << 4;
			c = gdb_getChar();
			xcksum += hex(c);

			if (cksum != xcksum) {
				gdb_putChar('-'); 	/* checksum failed */
			} else {
				gdb_putChar('+');	/* checksum success, ack*/

				if (buf[2] == ':') {
					gdb_putChar(buf[0]);
					gdb_putChar(buf[1]);

					return &buf[3];
				}

				return buf;
			}
		}
	}

	return NULL; 
}

/*
 * Send a packet, computing it's checksum, waiting for it's acknoledge.
 * If there is not ack, packet will be resent.
 */
static void kgdb_put_packet(char *buf)
{
    uint8_t cksum;
    printf("Outputting %s", buf);
    for (;;) {
        gdb_putChar('$');
        for (cksum = 0; *buf; buf++) {
            cksum += *buf;
            gdb_putChar(*buf);
        }
        gdb_putChar('#');
        gdb_putChar(hexchars[cksum >> 4]);
        gdb_putChar(hexchars[cksum % 16]);
        if (gdb_getChar() == '+')
            break;
    }
}

/**
 * Translates from registers to a registers buffer that gdb expects.
 */
static void regs2buf(register_set_t *regs) {
	for (int i = 0; i < NUM_REGS64; i++) {
		regs->registers_64[i] = reg_state.registers_64[i];
	}
    regs->cpsr = reg_state.cpsr;
}

/**
 * Translates from gdb registers buffer to registers
 */
static void buf2regs(register_set_t *regs) {
	for (int i = 0; i < NUM_REGS64; i++) {
        reg_state.registers_64[i] = regs->registers_64[i];
	}
    reg_state.cpsr = reg_state.cpsr | regs->cpsr;
}

/**
 * Returns a ptr to last char put in buf or NULL on error (cannot read memory)
 */
static char *mem2hex(char *mem, char *buf, int size)
{
    int i;
    unsigned char c;

    for (i = 0; i < size; i++, mem++) {
        //if (!is_mapped((virt_t)mem & ~0xFFF))
        //    return NULL;
       	c = *mem;
        *buf++ = hexchars[c >> 4];
        *buf++ = hexchars[c % 16];
    }
    *buf = 0;
    return buf;
}


static char *regs_buf2hex(register_set_t *regs, char *buf) {
    /* First we handle the 64-bit registers */
    buf = mem2hex((char *) regs->registers_64, buf, NUM_REGS64 * sizeof(seL4_Word));
    return mem2hex((char *) &regs->cpsr, buf, sizeof(seL4_Word) / 2);
}

/**
 * Returns a ptr to the char after last memory byte written
 *  or NULL on error (cannot write memory)
 */
static char *hex2mem(char *buf, char *mem, int size)
{
    int i;
    unsigned char c;

    for (i = 0; i < size; i++, mem++) {
        // if (!is_mapped((virt_t)mem & ~0xFFF)) {
        //     kprintf("not mapped %x\n", mem);
        //     return NULL;
        c = hex(*buf++) << 4;
        c += hex(*buf++);
        *mem = c;
    }
    return mem;
}

static char *hex2regs_buf(char *buf, register_set_t *regs) {
    hex2mem(buf, (char *) regs->registers_64, NUM_REGS64 * sizeof(seL4_Word));
    /* 2 hex characters per byte*/
    return hex2mem(buf + 2 * NUM_REGS64 * sizeof(seL4_Word), (char *) &regs->cpsr, sizeof(seL4_Word)/2);
}


int initialise_connection() {
    struct sockaddr_un addr;

    listen_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listen_socket == -1) {
        printf("Could not create socket\n");
        return -1; 
    }

    memset(&addr, 0, sizeof(struct sockaddr_un));

    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCK_NAME, sizeof(addr.sun_path) - 1);
    int ret = bind(listen_socket, (const struct sockaddr *)&addr, sizeof(struct sockaddr_un));
    if (ret == -1) {
        printf("Could not bind socket %d\n", errno);
        return -1; 
    }

    ret = listen(listen_socket, 20);
    if (ret == -1) {
        printf("Listen failed\n");
        return -1; 
    }
        
    data_socket = accept(listen_socket, NULL, NULL);
    if (data_socket == -1) {
        printf("Error in accepting\n");
        return -1; 
    }

    return 0;
}

void intHandler(int sig) {
    close(data_socket);
    close(listen_socket);
    unlink(SOCK_NAME);
    exit(0);
}

int main(void) {
    char *ptr;
	register_set_t regs;

    /* 
     * Useful resources:
     * Commands of the form qX : https://sourceware.org/gdb/onlinedocs/gdb/General-Query-Packets.html
     * General commands : https://sourceware.org/gdb/onlinedocs/gdb/Packets.html
     * Stop-reply (for ?) : https://sourceware.org/gdb/onlinedocs/gdb/Stop-Reply-Packets.html 
    */

    if (initialise_connection()) {
        return 1; 
    }

    signal(SIGINT, intHandler);

    printf("Connection initialized...\n");

	while (1) {
		ptr = kgdb_get_packet();
		printf("\n\nHi. The first message I received was: %s\n\n", ptr);
        kgdb_out[0] = 0;
    	// seL4_Word regs[NUM_REGS];


		if (*ptr == 'g') {
			regs2buf(&regs);
            regs_buf2hex(&regs, kgdb_out);
		} else if (*ptr == 'G') {
            hex2regs_buf(++ptr, &regs);
            buf2regs(&regs);
			strcpy(kgdb_out, "OK");
        } else if (*ptr == 'm') {
            if (sscanf)
        }
        
		} else if (*ptr == 'c' || *ptr == 's') {
			// seL4_Word addr; 
			int stepping = *ptr == 's' ? 1 : 0;
			ptr++;
			(void) stepping;

			/* TODO: Support continue from an address and single step */
            // if (sscanf(ptr, "%x", &addr))
                // current_task->regs.eip = addr;
            // if (stepping)
                // current_task->regs.eflags |= 0x100; /* Set trap flag. */
            // else
                // current_task->regs.eflags &= ~0x100; /* Clear trap flag */
            

            // TODO: Maybe need to flush i-cache?
            break;
		} else if (*ptr == 'q') {
			if (strncmp(ptr, "qSupported", 9) == 0) {
                /* TODO: This may eventually support more features */
                snprintf(kgdb_out, sizeof(kgdb_out), 
                    "qSupported:PacketSize=%lx;QThreadEvents+;swbreak+", sizeof(kgdb_in));
            } else if (strncmp(ptr, "qfThreadInfo", strlen("qfThreadInfo")) == 0) {
                /* This should eventually get an actual list of thread IDs */
                strcpy(kgdb_out, "m1l");
            } else if (strncmp(ptr, "qC", strlen("qC")) == 0) {
                strcpy(kgdb_out, "QC1");
            }
		} else if (*ptr == 'H') {
            /* TODO: THis should eventually do something */
            strcpy(kgdb_out, "OK");
        } else if (strncmp(ptr, "qTStatus", strlen("qTStatus")) == 0) {
            /* TODO: THis should eventually work in the non startup case */
            strcpy(kgdb_out, "T0");
        } else if (*ptr == '?') {
            /* TODO: This should eventually report more reasons than swbreak */
            strcpy(kgdb_out, "T05swbreak:;");
        } 

        kgdb_put_packet(kgdb_out);
	}

    close(data_socket);
    close(listen_socket);
    unlink(SOCK_NAME);
}