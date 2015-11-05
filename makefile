CC=clang
CFLAGS = -g -Wall

DEPS = bsd_pcap.h

PROGRAM = pcap

TARGET1 = bsd_pcap 

LFLAGS = -lpcap

all: $(PROGRAM)

$(PROGRAM): $(TARGET1).c
	$(CC) $(CFLAGS) -o $(TARGET1).c $(LFLAGS)

clean:
	rm -f $(PROGRAM) $(TARGET1)
