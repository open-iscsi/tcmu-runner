CFLAGS=-Wall -g -I /usr/include/libnl3 `pkg-config --cflags gio-unix-2.0`
LDLIBS=-lnl-3 -lnl-genl-3 -ldl -lpthread `pkg-config --libs gio-unix-2.0`

OBJECTS=main.o api.o tcmuhandler-generated.o

all: tcmu-runner handler_file.so handler_glfs.so

GDBUS_GENERATED = \
	tcmuhandler-generated.c \
	tcmuhandler-generated.h

$(GDBUS_GENERATED): tcmu-handler.xml Makefile
	gdbus-codegen tcmu-handler.xml \
	--generate-c-code tcmuhandler-generated \
	--c-generate-object-manager \
	--interface-prefix org.kernel

tcmu-runner: $(GDBUS_GENERATED) $(OBJECTS)
	$(CC) $(CFLAGS) $(OBJECTS) -fPIC -o tcmu-runner $(LDLIBS) -Wl,-E

handler_file.so: file_example.c
	$(CC) -shared $(CFLAGS) -fPIC file_example.c -o handler_file.so

handler_glfs.so: glfs.c
	$(CC) -shared $(CFLAGS) -fPIC glfs.c -o handler_glfs.so -lgfapi

.PHONY: clean
clean:
	rm -f *~ *.o tcmu-runner *.so
