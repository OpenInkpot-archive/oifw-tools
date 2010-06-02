

oifw-extract: oifw-extract.o
	$(CC) $(LDFLAGS) -static oifw-extract.o -lz -o $@

clean:
	rm -f oifw-extract.o oifw-extract
