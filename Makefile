
SHELL = /bin/sh

RM = rm -f
CFLAGS = -g -O2 -Wall

INCS = $(shell pkg-config --cflags gnome-keyring-1 glib-2.0)
LIBS = $(shell pkg-config --libs gnome-keyring-1 glib-2.0)

.SUFFIXES:

PROGRAM = gnome-keyring-cli
OBJS =

all: $(PROGRAM)

%.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(INCS) -c $<

$(PROGRAM): %: %.o $(OBJS)
	$(CC) -o $@ $(LDFLAGS) $^ $(LIBS)

.PHONY: all clean
clean:
	-$(RM) $(PROGRAM) $(patsubst %,%.o,$(PROGRAM)) $(OBJS)
