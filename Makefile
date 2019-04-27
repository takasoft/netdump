CC = gcc
PROG = netdump
# CCOPT = -g -xansi -signed -g3
DEFS =

# Standard CFLAGS
CFLAGS = $(CCOPT) $(DEFS) $(INCLS)

# Standard LDFLAGS
LDFLAGS =  -L/usr/local/lib

# Standard LIBS
LIBS = -lpcap 

.c.o:
	@rm -f $@
	$(CC) $(CFLAGS) -c ./$*.c

CSRC =	netdump.c \
	util.c setsignal.c

SRC =	$(CSRC) $(LOCALSRC)

OBJ =	$(CSRC:.c=.o) $(GENSRC:.c=.o) $(LOCALSRC:.c=.o) 
HDR =

CLEANFILES = $(PROG) $(OBJ)

all: $(PROG)

$(PROG): $(OBJ) 
	@rm -f $@
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJ) $(LIBS)

clean:
	rm -f $(CLEANFILES)
