all:
	gcc -o arp_discover arp_discover.c -lpthread -Wall
	gcc -o arp_poisoning arp_poisoning.c -lpthread -Wall

clean:
	rm -f arp_poisoning arp_discover

