CFLAGS=-Wall -g -I /usr/include/libnl3
LDLIBS=-lnl-3 -lnl-genl-3 -ldl -lpthread

OBJECTS=main.o api.o

all: tcmu-runner handler_file.so

tcmu-runner: $(OBJECTS)
	$(CC) $(CFLAGS) $(OBJECTS) -fPIC -o tcmu-runner $(LDLIBS) -Wl,-E

handler_file.so: file_example.c
	$(CC) -shared $(CFLAGS) -fPIC file_example.c -o handler_file.so

.PHONY: clean
clean:
	rm -f *~ *.o tcmu-runner *.so
