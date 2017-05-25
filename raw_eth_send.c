#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>

#define MAC_ADDR_LEN 6
#define BUFFER_SIZE 1600
#define MAX_DATA_SIZE 1500
#define ARP_HDRLEN 28

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

int getip(char *ifname, char *sender_ip){
	int fd;
	struct ifreq ifr;

	fd = socket(AF_INET, SOCK_DGRAM, 0);

	/* I want to get an IPv4 IP address */
	ifr.ifr_addr.sa_family = AF_INET;

	/* I want IP address attached to "eth0" */
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);

	ioctl(fd, SIOCGIFADDR, &ifr);

	close(fd);

	sprintf(sender_ip, "%s", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));

	return 0;
}

int main(int argc, char *argv[])
{
	int fd;
	struct ifreq if_idx;
	struct ifreq if_mac;
	struct sockaddr_ll socket_address;
	char ifname[IFNAMSIZ];
	int frame_len = 0;
	char buffer[BUFFER_SIZE];
	char dest_mac[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; //broadcast
	short int ethertype = htons(0x0806);

	arp_hdr arphdr;

	if (argc != 2) {
		printf("Usage: %s iface\n", argv[0]);
		return 1;
	}
	strcpy(ifname, argv[1]);

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
	int i;
	char sender_ip[15];
	char target_ip[15];

	char network[15] = "10.0.0.";
	char host [3];

	// get sender ip
	getip(ifname, sender_ip);
	printf("sender: %s\n", sender_ip);
	inet_pton (AF_INET, sender_ip, &arphdr.sender_ip);

	for(i=1; i < 255; i++){
		// set host number
		memset(host, 0, sizeof(host));
		sprintf(host, "%d", i);

		// concat network + host number
		memset(target_ip, 0, sizeof(target_ip));
		strcat(target_ip, network);
		strcat(target_ip, host);

		printf("target: %s\n", target_ip);
		inet_pton (AF_INET, target_ip, &arphdr.target_ip);

		memcpy (buffer + frame_len, &arphdr, ARP_HDRLEN * sizeof (uint8_t));
		frame_len += ARP_HDRLEN;

		/* Envia pacote */
		if (sendto(fd, buffer, frame_len, 0, (struct sockaddr *) &socket_address, sizeof (struct sockaddr_ll)) < 0) {
			perror("send");
			close(fd);
			exit(1);
		}

		printf("Pacote enviado.\n");
		frame_len -= ARP_HDRLEN;
	}

	
	close(fd);
	return 0;
}