#
# Makefile for the SUPERMAN daemon.
#
# Written by Dr Jodie Wetherall <wj88@gre.ac.uk>
#
# Dependancies:
# build-essential make pkg-config libnl-3-dev libnl-genl-3-dev libssl-dev

CC=gcc
CFLAGS= -Wno-write-strings `pkg-config --cflags libnl-3.0 libnl-genl-3.0 openssl`
SRCS=$(shell find ../src/ -name '*.c')
OBJS=$(notdir $(patsubst %.c,%.o,$(SRCS)))
LIBS= `pkg-config --libs libnl-3.0 libnl-genl-3.0 openssl` -ldl
OUTPUT=superman

.DEFAULT_GOAL := all
.PHONY: clean top

all: main-build

main-build:
	$(info Building SUPERMAN daemon)
	@$(MAKE) --no-print-directory $(OUTPUT)

$(OUTPUT): $(OBJS)
	@echo '  LD      $(notdir $@)'
	@$(CC) $(CFLAGS) -o $@ $^  $(LIBS)

%.o: ../src/%.c
	@echo '  CC      $(notdir $^)'
	@$(CC) $(CFLAGS) -c -o $@ $^

clean:
	$(info Cleaning SUPERMAN daemon)
	@-rm -f *.o ../src/*.o *~ $(OUTPUT) core
