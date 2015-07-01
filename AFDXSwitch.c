#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>  
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h> 

 /* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* IP header length are 20 bytes */
#define SIZE_IP 20

/* UDP header length are 8 bytes */
#define SIZE_UDP 8

struct  ethernetHeader {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

struct ipheader{
	unsigned char ip_header_len:4; // 4-bit header length (in 32-bit words) normally=5 (Means 20 Bytes may be 24 also)
	unsigned char ip_version :4; // 4-bit IPv4 version
	unsigned char ip_tos; // IP type of service
	unsigned short ip_total_length; // Total length
	unsigned short ip_id; // Unique identifier
 
	unsigned char ip_frag_offset :5; // Fragment offset field
 
	unsigned char ip_more_fragment :1;
	unsigned char ip_dont_fragment :1;
	unsigned char ip_reserved_zero :1;
 
	unsigned char ip_frag_offset1; //fragment offset
 
	unsigned char ip_ttl; // Time to live
	unsigned char ip_protocol; // Protocol(TCP,UDP etc)
	unsigned short ip_checksum; // IP checksum
	unsigned int ip_srcaddr; // Source address
	unsigned int ip_destaddr; // Source addres
}; //total ip header panjangnya 20 bytes

struct udpheader{
	 unsigned short source_port;     // Source port no.
	 unsigned short dest_port;       // Dest. port no.
	 unsigned short udp_length;      // Udp packet length
	 unsigned short udp_checksum;    // Udp checksum (optional)
};

void callback(u_char *useless,const struct pcap_pkthdr* header,const u_char* packet)
{
  	u_int i;
	struct ethernetHeader *ethdr=NULL; 
	struct ipheader *v4hdr=NULL;
	struct udpheader *uhdr=NULL;
	char *payload;
	int VlinkID;
	pcap_t* adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	int size_payload=58;
	


	//TypeCasting packet header

	ethdr = (struct ethernetHeader*)(packet);
	v4hdr = (struct ipheader*)(packet + SIZE_ETHERNET);
	uhdr  = (struct udpheader*)(packet + SIZE_ETHERNET + SIZE_IP);
	payload = (u_char *)(packet + SIZE_ETHERNET + SIZE_IP + SIZE_UDP);
	VlinkID = ethdr->ether_dhost[5];

	printf("\n---------------------------------------------------------------------\n");
	// Print all raw packet
	printf("\n Raw Packet : \n");
        // loop through the packet and print it as hexidecimal representations of octets
        // We also have a function that does this similarly below: PrintData()
        for ( i=0; (i < header->caplen ) ; i++)
        {
            // Start printing on the next after every 16 octets
            if ( (i % 16) == 0) printf("\n");
 
            // Print each octet as hex (x), make sure there is always two characters (.2).
            printf("%.2d ", packet[i]);
        }
 
        // Add two lines between packets
        printf("\n\n");
	printf("\n---------------------------------------------------------------------\n");
	/* print source and destination IP addresses */
	printf("From		: %s\n", inet_ntoa(*(struct in_addr *)&v4hdr->ip_srcaddr));
	printf("To		: %s\n", inet_ntoa(*(struct in_addr *)&v4hdr->ip_destaddr));
	printf("Virtual Link ID : %.2x",VlinkID);
	printf("\n---------------------------------------------------------------------\n");
	printf("\nPayload : \n");
	
	/* hex */
	  for ( i=0; (i < size_payload ) ; i++)
        {
            // Start printing on the next after every 16 octets
            if ( (i % 16) == 0) printf("\n");
 
            // Print each octet as hex (x), make sure there is always two characters (.2).
            printf("%.2x ", *payload);
	    payload++;
        }

	//Packet Forwarding

	if(VlinkID == 0x4) 
	     {
		
		adhandle = pcap_open_live("eth0", 65536, 1,1, errbuf);	
		pcap_sendpacket(adhandle, packet, header->len); 
	     } 
	else if( VlinkID == 0x3)
	     {
		printf("Packet Rejected"); 
	     }
 
        // Add two lines between packets
        printf("\n\n");
	printf("\n---------------------------------------------------------------------\n");

	
}

void pktinit(char *dev) /*function: for individual interface packet capturing*/
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* adhandle;
    struct bpf_program fp;        /* to hold compiled program */
    bpf_u_int32 pMask;            /* subnet mask */
    bpf_u_int32 pNet;             /* ip address*/
    pcap_if_t *alldevs, *d;
    char dev_buff[64] = {0};
    int i =0;
    pcap_lookupnet(dev, &pNet, &pMask, errbuf);
    adhandle = pcap_open_live(dev, 65536, 1,1, errbuf);
    if(adhandle == NULL)
    {
        printf("pcap_open_live() failed due to [%s]\n", errbuf);
        
    }
    printf("listening from [%s]\n", dev);
    pcap_loop(adhandle, 0, callback, NULL);
	
    pcap_close(adhandle);
    
}
int pid,i;
int main(int argc, char **argv)
{
    
    if(argc < 2) /*command <eth0> [eth1]...*/
    {
        printf("command needs ethernet name");
        return 0;
    }

    for(i = 1; i < argc; i++)
    {
        
        if ((pid=fork())!=0)
 	{

        pktinit(argv[i]);
        
	}
      
    }

    
    return 0;
}
