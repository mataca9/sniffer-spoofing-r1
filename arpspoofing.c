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
#define IF_DEBUG 1

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

int main(int argc, char *argv[])
	int fd;
	struct ifreq if_idx;
	struct ifreq if_mac;
	struct sockaddr_ll socket_address;
	int frame_len = 0;
	char buffer[BUFFER_SIZE];
	char dest_mac[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; //broadcast
	short int ethertype = htons(0x0806);
    char ifname[IFNAMSIZ];
    char iptarget[15];

    if (argc != 3) {
		printf("Usage: %s iface target\n", argv[0]);
		return 1;
	}
	strcpy(ifname, argv[1]);
	strcpy(iptarget, argv[2]);

	arp_hdr arphdr;

	/* Cria um descritor de socket do tipo RAW */
	if ((fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
		perror("socket");
		exit(1);
	}

	/* Obtem o indice da interface de rede */
	memset(&if_idx, 0, sizeof (struct ifreq));
	strncpy(if_idx.ifr_name, ifname, IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFINDEX, &if_idx) < 0) {
		perror("SIOCGIFINDEX");
		exit(1);
	}


	/* Obtem o endereco MAC da interface local */
	memset(&if_mac, 0, sizeof (struct ifreq));
	strncpy(if_mac.ifr_name, ifname, IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFHWADDR, &if_mac) < 0) {
		perror("SIOCGIFHWADDR");
		exit(1);
	}

	/* Indice da interface de rede */
	socket_address.sll_ifindex = if_idx.ifr_ifindex;

	/* Tamanho do endereco (ETH_ALEN = 6) */
	socket_address.sll_halen = ETH_ALEN;

	/* Endereco MAC de destino */
	memcpy(socket_address.sll_addr, dest_mac, MAC_ADDR_LEN);

	/* Preenche o buffer com 0s */
	memset(buffer, 0, BUFFER_SIZE);

	/* Monta o cabecalho Ethernet */

	/* Preenche o campo de endereco MAC de destino */	
	memcpy(buffer, dest_mac, MAC_ADDR_LEN);
	frame_len += MAC_ADDR_LEN;

	/* Preenche o campo de endereco MAC de origem */
	memcpy(buffer + frame_len, if_mac.ifr_hwaddr.sa_data, MAC_ADDR_LEN);
	frame_len += MAC_ADDR_LEN;

	/* Preenche o campo EtherType */
	memcpy(buffer + frame_len, &ethertype, sizeof(ethertype));
	frame_len += sizeof(ethertype);

	/* Monta o cabecalho ARP */

	/* Hardware type (16 bits): 1 for ethernet */
	arphdr.htype = htons (1);

	/* Protocol type (16 bits): 2048 for IP */
	arphdr.ptype = htons (ETH_P_IP);

	/* Hardware address length (8 bits): 6 bytes for MAC address */
	arphdr.hlen = 6;

	/* Protocol address length (8 bits): 4 bytes for IPv4 address */
	arphdr.plen = 4;

	/* OpCode: 1 for ARP request */
	arphdr.opcode = htons (1);

	/* Sender hardware address (48 bits): MAC address */
	memcpy (&arphdr.sender_mac, if_mac.ifr_name, 6 * sizeof (uint8_t));

	/* Target hardware address (48 bits): zero, since we don't know it yet. */
	memset (&arphdr.target_mac, 0, 6 * sizeof (uint8_t));
	
	// help vars for multiple sends
	int i = 0;
	int range_host = 0;
	int s_ip = 0;
	char sender_ip[15];
	char target_ip[15];

	unsigned char target_byte[4];

	// get sender ip
	s_ip = getip(ifname, sender_ip);

	//get renge hosts
	range_host = getrangeip(ifname);

	inet_pton (AF_INET, sender_ip, &arphdr.sender_ip);

	//ip destinatário fateado
    target_byte[0] = s_ip & 0xFF;
    target_byte[1] = (s_ip >> 8) & 0xFF;
    target_byte[2] = (s_ip >> 16) & 0xFF;
	
	for(i=1; i < range_host; i++){

    	target_byte[3] = i;

		// set host number
		memset(target_ip, 0, sizeof(target_ip));
		sprintf(target_ip, "%d.%d.%d.%d", target_byte[0],target_byte[1],target_byte[2],target_byte[3]);

		inet_pton (AF_INET, target_ip, &arphdr.target_ip);

		memcpy (buffer + frame_len, &arphdr, ARP_HDRLEN * sizeof (uint8_t));
		frame_len += ARP_HDRLEN;

		// Envia pacote 
		if (sendto(fd, buffer, frame_len, 0, (struct sockaddr *) &socket_address, sizeof (struct sockaddr_ll)) < 0) {
			perror("send");
			close(fd);
			exit(1);
		}

		if(IF_DEBUG){
			printf("Broadcast\tARP\tWho has %s? Tell %s\n", target_ip, sender_ip);
		}
		frame_len -= ARP_HDRLEN;
	}
	
	close(fd);
    pthread_exit(NULL);
}

int main(int argc, char *argv[])
{


    pthread_t thread_dicover;
    pthread_t thread_sender;

    pthread_mutex_init(&mutex, NULL);
    //pthread_mutex_lock(&mutex);

    if (pthread_create(&thread_dicover, NULL, discover, NULL) != 0) {
	    printf("Erro ao criar a thread.\n");
	    exit(-1);
    }

    if (pthread_create(&thread_sender, NULL, sender, NULL) != 0) {
	    printf("Erro ao criar a thread.\n");
	    exit(-1);
    }
    pthread_exit(NULL);
}
