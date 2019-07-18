CFLAGS=-g -O2 -fstack-protector-strong -Wformat -Werror=format-security -Wall $(C_SYSTEMD)
LDFLAGS=-Wl,-z,relro $(shell pkg-config --libs tss2-esys libcrypto) $(LD_SYSTEMD)

ifdef WITH_SYSTEMD
CFLAGS +=-DWITH_SYSTEMD
LDFLAGS += $(shell pkg-config --libs libsystemd)
endif

all: tpm2-ssh-agent

clean:
	rm -f *.o tpm2-ssh-agent

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

tpm2-ssh-agent: main.o message.o keys.o list.o sign.o buffer.o socket.o log.o
	$(CC) -o tpm2-ssh-agent $^ $(CFLAGS) $(LDFLAGS)
