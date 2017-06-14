#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <math.h>
#include <limits.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <pthread.h>

#define MAC_ADDR_LEN 6
#define BUFFER_SIZE 1600
#define MAX_DATA_SIZE 1500
#define ARP_HDRLEN 28
#define IF_DEBUG 0

#define INT_TO_ADDR(_addr) \
(_addr & 0xFF), \
(_addr >> 8 & 0xFF), \
(_addr >> 16 & 0xFF), \
(_addr >> 24 & 0xFF)

typedef struct _arp_hdr arp_hdr;
struct _arp_hdr {
  uint16_t htype;
  uint16_t ptype;
  uint8_t hlen;
  uint8_t plen;
  uint16_t opcode;
  uint8_t sender_mac[6];
  uint8_t sender_ip[4];
  uint8_t target_mac[6];
  uint8_t target_ip[4];
};

char ifname[IFNAMSIZ];

void * sniffer(void *args)
{
	char buffer[BUFFER_SIZE];
	short int ethertype = htons(0x0806);
	char sender_ip[15];

	printf("Sniffing arp packets...\n");
	while (1) {
		unsigned char mac_dst[6];
		unsigned char mac_src[6];
		//unsigned char *arp;
		short int e_type;
		unsigned char ip_sd[4];
        

        short op_code;

		uint16_t htype;
		uint16_t ptype;
		uint8_t hlen;
		uint8_t plen;
		uint16_t opcode;
		uint8_t sender_mac[6];
		uint8_t sender_ip[4];
		uint8_t target_mac[6];
		uint8_t target_ip[4];


		char sender_mac[17];
        int fd;
        if ((fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
	        perror("socket");
	        exit(1);
        }		

		while(recv(fd,(char *) &buffer, BUFFER_SIZE, 0) > 0){
    	
		  
			/* Copia o conteudo do cabecalho Ethernet */
			memcpy(mac_dst, buffer, sizeof(mac_dst));
			memcpy(mac_src, buffer+sizeof(mac_dst), sizeof(mac_src));
			memcpy(&e_type, buffer+sizeof(mac_dst)+sizeof(mac_src), sizeof(e_type));
			e_type = ntohs(e_type);
			
			memcpy(ip_sd, buffer+sizeof(mac_dst)+sizeof(mac_src)+(16*sizeof(char)), sizeof(ip_sd));
    	    memcpy(&op_code, buffer+sizeof(mac_dst)+sizeof(mac_src)+(8*sizeof(char)), sizeof(op_code));

			op_code = ntohs(op_code);
    	    if (htons(e_type) == ethertype && op_code == 2) { 
				printf("\n--- Received:\n");
				printf("MAC destino: %02x:%02x:%02x:%02x:%02x:%02x\n", 
    	                    mac_dst[0], mac_dst[1], mac_dst[2], mac_dst[3], mac_dst[4], mac_dst[5]);

				memset(sender_mac, 0, sizeof(sender_mac));
				sprintf(sender_mac, " %02x:%02x:%02x:%02x:%02x:%02x", mac_src[0], mac_src[1], mac_src[2], mac_src[3], mac_src[4], mac_src[5]);
				printf("MAC origem:  %s\n", sender_mac);

				printf("EtherType: 0x%04x\n", e_type);
				
				memset(sender_ip, 0, sizeof(sender_ip));
				sprintf(sender_ip, "%d.%d.%d.%d", ip_sd[0], ip_sd[1], ip_sd[2], ip_sd[3]);
				printf("IP sender: %s\n", sender_ip);

				printf("---\n");

				setArpTable(sender_ip, sender_mac);			
			}
		}
	}

    pthread_exit(NULL);
}

int main(int argc, char *argv[])
{
    if (argc != 2) {
		printf("Usage: %s iface\n", argv[0]);
		return 1;
	}
	strcpy(ifname, argv[1]);

	sniffer();

	return 0;
}


