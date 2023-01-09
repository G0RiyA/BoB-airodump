LDLIBS += -lpcap

all: airodump

airodump: airodump.cpp

clean:
	rm -f airodump *.o

