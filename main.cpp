#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

void print_mac(const u_char* mac){
     printf("%02X%02X%02X%02X%02X%02X\n", mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
}

void print_ip(const u_char* ip){
     printf("%u.%u.%u.%u\n", ip[0],ip[1],ip[2],ip[3]);
}

void print_port(const u_char* port){
     printf("%d\n", port[0] << 8 | port[1]);
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;

    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    if((packet[12]<<8|packet[13])== 0x0800){
        if((packet[23])== 0x06){
            printf("################################\n");
            printf("#        Packet Capture        #\n");
            printf("################################\n");
            printf("%u bytes captured\n", header->caplen);
            //printf("Packet length : %d\n",header->len);


            printf("Source MAC : ");
            print_mac(&packet[6]);

            printf("Destination MAC : ");
            print_mac(&packet[0]);

            printf("Source IP : ");
            print_ip(&packet[26]);

            printf("Destination IP : ");
            print_ip(&packet[30]);

            //printf("Destination IP : %u.%u.%u.%u\n", packet[30],packet[31],packet[32],packet[33]);

            printf("Source PORT : ");
            print_port(&packet[34]);

            printf("Destination PORT : ");
            print_port(&packet[36]);

            //printf("Destination PORT : %d\n", packet[36] << 8 | packet[37] );


            printf("TCP offset : %d\n",(packet[46]>>4)*4 + 34);

            int offset = (packet[46]>>4)*4 + 34;



             printf("TCP Data\n");
             printf("==============================\n");

             if(packet[offset]){
                int i=0;
                while(1){
                    if(i==10)
                        break;
                    printf("%02x ",packet[offset+i]);
                    i++;
                    if(!packet[offset+i])
                        break;

                }
             }

            printf("\n");
            printf("==============================\n");


        }
    }

  }

  pcap_close(handle);
  return 0;
}
