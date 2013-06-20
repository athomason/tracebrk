PLATFORM=$(shell uname -p)
CFLAGS=-g -O2 -Wall
LDLIBS=-lunwind-ptrace -lunwind-$(PLATFORM)
EXE=tracebrk

all: $(EXE)

test: test/grow
	$(MAKE) -C test grow

clean:
	-rm -f $(EXE) test/grow
