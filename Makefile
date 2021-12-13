CFLAGS	+= -Wall   -g 
LDFLAGS += -Wall 

all: server


server.o: server.c server.h
	gcc ${CFLAGS} -c server.c -o server.o 

server:  server.o
	gcc ${LDFLAGS}  server.o -lm -o server

clean:
	rm -rf *.o 