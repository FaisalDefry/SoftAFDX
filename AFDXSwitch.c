#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>  
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h> 
#include <libconfig.h>

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
	pcap_t* adhandle2;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	int size_payload=58;
	config_t cfg;               /*Returns all parameters in this structure */
    	config_setting_t *setting;
    	const char *dev1, *dev2, *dev3, *dev4, *dev5, *dev6, *dev7, *dev8, *dev9, *dev10 ;
    	int EsAm, EsAu, EsBm, EsBu, EsCm, EsCu;
    
 
   	char *config_file_name = "VLConfig.cfg";


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

	/*Initialization */
    config_init(&cfg);
 
    /* Read the file. If there is an error, report it and exit. */
    if (!config_read_file(&cfg, config_file_name))
    {
        printf("\n%s:%d - %s", config_error_file(&cfg), config_error_line(&cfg), config_error_text(&cfg));
        config_destroy(&cfg);
        
    }
 
    /* Get the configuration file name. */
    if (config_lookup_string(&cfg, "filename", &dev1))
        printf("\nFile Type: %s", dev1);
    else
        printf("\nNo 'filename' setting in configuration file.");
 
    /*Read the parameter group*/


 setting = config_lookup(&cfg, "VirtualLinkConfig");
    if (setting != NULL)
    {
        /*Read the string*/
        if (config_setting_lookup_int(setting, "EsAm", &EsAm))
        {
         //   printf("\nVL ID EndSystem A: %.2x ", EsA);
        }
        else
            printf("\nNo 'param1' setting in configuration file.");
		
	/*Read the string*/
        if (config_setting_lookup_int(setting, "EsAu", &EsAu))
        {
         //   printf("\nVL ID EndSystem A: %.2x ", EsA);
        }
        else
            printf("\nNo 'param1' setting in configuration file.");	
		
 
        /*Read the string*/
        if (config_setting_lookup_int(setting, "EsBm", &EsBm))
        {
         //   printf("\nVL ID EndSystem B: %.2x ", EsB);
        }
        else
            printf("\nNo 'param2' setting in configuration file.");
 
        printf("\n");
		
		/*Read the string*/
        if (config_setting_lookup_int(setting, "EsBu", &EsBu))
        {
         //   printf("\nVL ID EndSystem B: %.2x ", EsB);
        }
        else
            printf("\nNo 'param2' setting in configuration file.");
 
        printf("\n");
		
		
		/*Read the string*/
        if (config_setting_lookup_int(setting, "EsCm", &EsCm))
        {
         //   printf("\nVL ID EndSystem B: %.2x ", EsB);
        }
        else
            printf("\nNo 'param2' setting in configuration file.");
 
        printf("\n");
		
		/*Read the string*/
        if (config_setting_lookup_int(setting, "EsCu", &EsCu))
        {
         //   printf("\nVL ID EndSystem B: %.2x ", EsB);
        }
        else
            printf("\nNo 'param2' setting in configuration file.");
 
        printf("\n");

	/*Read the string*/
        if (config_setting_lookup_string(setting, "VLID01a", &dev2))
        {
        //    printf("\nVL 01 Destination Port: %s", dev2);
        }
        else
            printf("\nNo 'param1' setting in configuration file.");
		
		 if (config_setting_lookup_string(setting, "VLID01b", &dev8))
        {
        //    printf("\nVL 01 Destination Port: %s", dev2);
        }
        else
            printf("\nNo 'param1' setting in configuration file.");
 
        /*Read the string*/
        if (config_setting_lookup_string(setting, "VLID02a", &dev3))
        {
        //    printf("\nVL 02 Destination Port: %s", str3);
        }
        else
            printf("\nNo 'param2' setting in configuration file.");
		
		 if (config_setting_lookup_string(setting, "VLID02b", &dev9))
        {
        //    printf("\nVL 02 Destination Port: %s", str3);
        }
        else
            printf("\nNo 'param2' setting in configuration file.");
		
		
		if (config_setting_lookup_string(setting, "VLID03a", &dev4))
        {
        //    printf("\nVL 01 Destination Port: %s", dev2);
        }
        else
            printf("\nNo 'param1' setting in configuration file.");
		
		if (config_setting_lookup_string(setting, "VLID03b", &dev10))
        {
        //    printf("\nVL 01 Destination Port: %s", dev2);
        }
        else
            printf("\nNo 'param1' setting in configuration file.");
 
        /*Read the string*/
        if (config_setting_lookup_string(setting, "VLID04", &dev5))
        {
        //    printf("\nVL 02 Destination Port: %s", str3);
        }
        else
            printf("\nNo 'param2' setting in configuration file.");
		
		    if (config_setting_lookup_string(setting, "VLID05", &dev6))
        {
        //    printf("\nVL 01 Destination Port: %s", dev2);
        }
        else
            printf("\nNo 'param1' setting in configuration file.");
 
        /*Read the string*/
        if (config_setting_lookup_string(setting, "VLID06", &dev7))
        {
        //    printf("\nVL 02 Destination Port: %s", str3);
        }
        else
            printf("\nNo 'param2' setting in configuration file.");
 
        printf("\n");

	}
	int EndSystem = VlinkID;
/*	switch(EndSystem)
    {
    case EsA :
        adhandle = pcap_open_live(str2, 65536, 1,1, errbuf);	
	pcap_sendpacket(adhandle, packet, header->len);
        break;
    case EsB :
        adhandle = pcap_open_live(str3, 65536, 1,1, errbuf);	
	pcap_sendpacket(adhandle, packet, header->len);
        break;
    } */
	
	if(EndSystem == EsAm) 
	     {
		
		adhandle = pcap_open_live(dev2, 65536, 1,1, errbuf);	
		pcap_sendpacket(adhandle, packet, header->len); 
		pcap_close(adhandle);
		adhandle2 = pcap_open_live(dev8, 65536, 1,1, errbuf);	
		pcap_sendpacket(adhandle2, packet, header->len); 
	     } 
	if( EndSystem == EsBm)
	     {
		adhandle = pcap_open_live(dev3, 65536, 1,1, errbuf);	
		pcap_sendpacket(adhandle, packet, header->len); 
		pcap_close(adhandle);
		adhandle2 = pcap_open_live(dev9, 65536, 1,1, errbuf);	
		pcap_sendpacket(adhandle2, packet, header->len); 
	     } 
		 
	if( EndSystem == EsCm)
	     {
		adhandle = pcap_open_live(dev4, 65536, 1,1, errbuf);	
		pcap_sendpacket(adhandle, packet, header->len); 
		pcap_close(adhandle);
		adhandle2 = pcap_open_live(dev10, 65536, 1,1, errbuf);	
		pcap_sendpacket(adhandle2, packet, header->len); 
	     } 	 
		 
	if( EndSystem == EsAu)
	     {
		adhandle = pcap_open_live(dev5, 65536, 1,1, errbuf);	
		pcap_sendpacket(adhandle, packet, header->len); 
		pcap_close(adhandle);
		
	     } 		 
	if( EndSystem == EsBu)
	     {
		adhandle = pcap_open_live(dev6, 65536, 1,1, errbuf);	
		pcap_sendpacket(adhandle, packet, header->len); 
		pcap_close(adhandle);
		
	     } 

	if( EndSystem == EsCu)
	     {
		adhandle = pcap_open_live(dev7, 65536, 1,1, errbuf);	
		pcap_sendpacket(adhandle, packet, header->len); 
		pcap_close(adhandle);
		
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
    pcap_setdirection(adhandle,PCAP_D_IN);
    pcap_compile(adhandle, &fp, "len <= 64 and len >= 1518", 1, pNet);
    pcap_setfilter(adhandle, &fp);
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
