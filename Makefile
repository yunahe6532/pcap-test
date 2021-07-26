all: pcap-test

pcap-test: pcap.o
	gcc -g -o pcap-test pcap.o -lpcap

pcap.o: 
	gcc -g -c -o pcap.o pcap.c

clean:
	rm -f pcap-test
	rm -f *.o
