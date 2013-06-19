PLATFORM=$(shell uname -p)
CFLAGS=-g -O2 -Wall
LDLIBS=-lunwind-ptrace -lunwind-$(PLATFORM)
EXE=tracebrk

all: $(EXE)

clean:
	-rm -f $(EXE)
