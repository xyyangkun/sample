CFLAGS += -c -I/usr/local/ssl/include
LDFLAGS += -L/usr/local/ssl/lib
LDFLAGS += -lssl -lcrypto -ldl

CC := g++

all:cli serv

cli:cli.o
	$(CC) cli.o $(LDFLAGS)  -o $@
serv:serv.o
	$(CC) serv.o $(LDFLAGS)  -o $@

cli.o:cli.cpp
	$(CC) $(CFLAGS) $^ -o $@
serv.o:serv.cpp
	$(CC) $(CFLAGS) $^ -o $@

clean:
	rm -rf *.o cli serv

.PHONY:cli serv clean

