all: arp_spoof

arp_spoof:  
	g++ -o arp_spoof main.cpp -lpcap

clean:
	rm -f arp_spoof
