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

void sniffer()
{
	char buffer[BUFFER_SIZE];
	short int ethertype = htons(0x0806);
	arp_hdr arpheader;

	printf("Sniffing arp packets...\n");
	while (1) {
		unsigned char mac_dst[6];
		unsigned char mac_src[6];
		short int e_type;	

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

			/* Valida se protocolo em cima e ARP */
    	    if (e_type == ethertype) {
				/* Copia conteudo para a struct de ARP */
				memcpy(&arpheader, buffer+sizeof(mac_dst)+sizeof(mac_src)+sizeof(e_type), sizeof(arpheader));
				
				/* Converte alguns dados para apresentacao */
				arpheader.htype = ntohs(arpheader.htype);
				arpheader.ptype = ntohs(arpheader.ptype);
				arpheader.hlen = ntohs(arpheader.hlen);
				arpheader.plen = ntohs(arpheader.plen);
				arpheader.opcode = ntohs(arpheader.opcode);
				
				/* Imprime conteudo */
				printf("\n--- ARP PACKET:\n");
				printf("- Hardware Type \t   %d\n", arpheader.htype);
				printf("- Protocol Type \t   %04x\n", arpheader.ptype);
				printf("- Hardware Address Length  %d\n", arpheader.hlen);
				printf("- Protocol Address Length  %d\n",arpheader.plen);
				printf("- Operation Code \t   %d", arpheader.opcode);

				if(arpheader.opcode == 1){
					printf(" (Request)\n");
				}else{
					printf(" (Reply)\n");
				}

				printf("- Sender MAC \t\t   %02x:%02x:%02x:%02x:%02x:%02x\n", arpheader.sender_mac[0], arpheader.sender_mac[1], arpheader.sender_mac[2], arpheader.sender_mac[3], arpheader.sender_mac[4], arpheader.sender_mac[5]);
				printf("- Sender IP \t\t   %d.%d.%d.%d\n", arpheader.sender_ip[0], arpheader.sender_ip[1], arpheader.sender_ip[2], arpheader.sender_ip[3]);
				printf("- Target MAC \t\t   %02x:%02x:%02x:%02x:%02x:%02x\n", arpheader.target_mac[0], arpheader.target_mac[1], arpheader.target_mac[2], arpheader.target_mac[3], arpheader.target_mac[4], arpheader.target_mac[5]);
				printf("- Target IP \t\t   %d.%d.%d.%d\n", arpheader.target_ip[0], arpheader.target_ip[1], arpheader.target_ip[2], arpheader.target_ip[3]);

				printf("---\n");
			}
		}
	}

    pthread_exit(NULL);
}

int main(int argc, char *argv[])
{
	sniffer();
	return 0;
}


