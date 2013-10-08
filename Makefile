CC=g++
CFLAGS=-w
LINKER=-lpcap
SOURCES=packet_reader.cpp
EXEC=packet_reader
all: 
		$(CC) $(CFLAGS) -o $(EXEC) $(SOURCES) $(LINKER)
