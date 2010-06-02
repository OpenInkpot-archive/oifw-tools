

all: oifw-extract

oifw-extract: oifw-extract.o
	gcc $(LDFLAGS) -static oifw-extract.o -lz -o $@

