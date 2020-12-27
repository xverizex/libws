LIBS=`pkg-config zlib,openssl --cflags --libs`
all:
	gcc -fPIC -shared ws.c $(LIBS) -o libws.so
clean:
	rm libws.so
