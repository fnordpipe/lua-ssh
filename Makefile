LDFLAGS += -shared -lssh2
CFLAGS += -fPIC

ifndef LUA
LUA = lua5.3
endif
ifdef LUA_INCDIR
INC += -I${LUA_INCDIR}
else
INC += -I/usr/include/${LUA}
endif

all: ssh.so

ssh.so:
	${CC} ${CFLAGS} ${INC} ${LDFLAGS} -o ssh.so src/ssh.c

clean:
	rm -f ssh.so
