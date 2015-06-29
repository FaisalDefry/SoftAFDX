#include <stdlib.h>

#include <stdio.h>

#include <string.h>

#include <pcap.h>

#include<sys/socket.h>

#include<arpa/inet.h> // for inet_ntoa()

#include<net/ethernet.h>

#include<netinet/udp.h>  //Provides declarations for udp header

#include<netinet/ip.h>   //Provides declarations for ip header







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



int main(int argc, char **argv)

{

	pcap_t *adhandle;

	char errbuf[PCAP_ERRBUF_SIZE];

	u_char packet[100];

	int i=0;

	u_char *dev;



	struct ipheader *v4hdr=NULL;

	struct udpheader *uhdr=NULL;



	printf("\n---------------------------------------------------------------------------------------\n");

	printf("\nAFDX TRANSMITTER PROTOTYPE\n");

	printf("\n---------------------------------------------------------------------------------------\n");

	//Pilih interface yang dipakai

	if(argv[1] == NULL) 

	{

	dev="eth0";

	printf ("\nusing interface eth0 as default.Try command './sendpacket <interface>' to specify interface\n ");



	} else 

 	{

	

	dev = argv[1];

	printf ("\nusing interface %s\n.",dev);

	

	}



	

	



	/* Open the adapter */

	if ((adhandle = pcap_open_live(dev,		// name of the device

							 65536,			// portion of the packet to capture. It doesn't matter in this case 

							 1,				// promiscuous mode (nonzero means promiscuous)

							 1000,			// read timeout

							 errbuf			// error buffer

							 )) == NULL)

	{

		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", argv[1]);

		return 2;

	}



	//ethernet header 14 bytes 0 - 13

	/* mac destination set sesuai AFDX part 7 */

	

	unsigned char vlinkID;



       /* To define virtual link ID */

    	printf("\nPlease enter Virtual Link ID : ");

    	scanf("%hhu",&vlinkID);

	printf("\n---------------------------------------------------------------------------------------\n");

	packet[0]=0;

	packet[1]=0;

	packet[2]=0;

	packet[3]=0;

	packet[4]=0;

	packet[5]=vlinkID; /* Virtual link ID */

	

	/* mac source to set sesuai AFDX part 7 */

	

	packet[6]=1;

	packet[7]=0;

	packet[8]=0;

	packet[9]=0;

	packet[10]=0;

	packet[11]=vlinkID; /* Virtual link ID */

	

	//type IP

	packet[12]=8;

	packet[13]=0;

	

	//header IP

	v4hdr = (struct ipheader *)&packet[14]; //lets point to the ip header portion byte ke 15(14) adalah awal header IP

	v4hdr->ip_version=4;

	v4hdr->ip_header_len=5;

	v4hdr->ip_tos = 0;

	v4hdr->ip_total_length = htons ( 100 );

	v4hdr->ip_id = htons(2);

	v4hdr->ip_frag_offset = 0;

	v4hdr->ip_frag_offset1 = 0;

	v4hdr->ip_reserved_zero = 0;

	v4hdr->ip_dont_fragment = 1;

	v4hdr->ip_more_fragment = 0;

	v4hdr->ip_ttl = 8;

	v4hdr->ip_protocol = IPPROTO_UDP;

	v4hdr->ip_srcaddr = inet_addr("0.0.0.0");

	v4hdr->ip_destaddr = inet_addr("0.0.0.0");

	v4hdr->ip_checksum = htons(29320);  //manual checksum



	//header UDP

	uhdr = (struct udpheader *)&packet[34];

	uhdr->dest_port = htons(1);

	uhdr->source_port = htons(1);

	uhdr->udp_length = htons(64);

	uhdr->udp_checksum = 0;





	/* Payload */

	for(i=40;i<100;i++)

	{

		packet[i]= i;

	}



	/* Send down the packet */

	printf("\nPacket Sent...\n");

	if (pcap_sendpacket(adhandle,	// Adapter

		packet,				// buffer with the packet

		100					// size

		) != 0)

	{

		fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(adhandle));

		return 3;

	}

	  

	printf("\n---------------------------------------------------------------------------------------\n");

	pcap_close(adhandle);	

	return 0;

	  

}



