/*
questions:  
Run in the background?
forward to alternate port, i.e., 5353
use several dns servers

TODO: need a queue of dnsHeader.id -> incoming ports, so we know which port
to respond to when a response comes in from upstream

And do I need to spoof the source address when I respond to a local request?

LICENSED UNDER GPL version 3
jeremiahcl at github.
*/
#include <stdio.h>
#include <unistd.h> 
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <sys/ioctl.h>
#include <net/if.h>  //defines IFF_UP and ifreq
#define BUFSIZE 2000
#define FILEBUFSIZE 512
#define DISPLAY 0
#define TRUE 1
#define FALSE 0
#include <errno.h>
#define REAL_DNS "8.8.4.4"
FILE *resolv;
#define MAX_BLACKLIST_SIZE 4500
unsigned char* BlacklistArray[MAX_BLACKLIST_SIZE];
unsigned int BlacklistArraySize = 0;
unsigned char buf[BUFSIZE];
unsigned char filebuf[FILEBUFSIZE];
int displayHeaderReceived(HEADER dnsHeader);
/* note: the google dns service is at 8.8.8.8 and 8.8.4.4 */

void initLoopback() {
  struct ifreq ifr;
  int skfd;
  char *name = "lo";  /*loopback network device*/
  
  /*make sure the loopback interface is up: */
  skfd = socket(AF_INET,SOCK_DGRAM,0);
  strcpy(ifr.ifr_name,name);
  if (ioctl(skfd, SIOCGIFFLAGS, &ifr) < 0) {
    perror("ioctl");
    close(skfd);
    exit(1);
  }
  if ((ifr.ifr_flags & IFF_UP) == 0) {
    printf("Error: The loopback interface (lo) is down\n");
    close(skfd);
    exit(1);
  }
  close(skfd);
}

int displayChar(int c)
{
  int w;
  if (c > 31 && c < 127) {
    printf(" (%c) ", c);
  }
  else {
    /* display as hex */
    w = (c >> 4) & 0xf;
    if (w < 10) w += 48;
    else  w += 87;
    printf(" %c",w);
    w = c & 0xf;
    if (w < 10) w += 48;
    else  w += 87;
    printf("%c ", w);
  }
  return 0;
}

int displayAnswer(int bytesReceived)
{
  int nanswers, nauth,x;
  HEADER dnsHeader;
  
  nanswers = buf[6] * 256 + buf[7];
  nauth = buf[8] * 256 + buf[9];
  if (1)
  {
    for (x=0;x < 12;x++) {
      displayChar(buf[x]);
    }
    printf("\n");
    for (x=12;x < bytesReceived;x++) {
      displayChar(buf[x]);
    }
    printf("\n");
    memcpy(&dnsHeader,buf,12);
    displayHeaderReceived(dnsHeader);
    printf("n answers = %d n authority RRs = %d\n", nanswers, nauth);
    printf("=======================================\n");
  }
}

int readResolvConf() {
  char *res;
  resolv = fopen("/etc/resolv.conf","r");
  if (resolv == NULL ) perror("fopen");
  res = fgets(buf,BUFSIZE,resolv);
  while (res) {
    printf("%s",buf);
    res = fgets(buf,BUFSIZE,resolv);
  }
  printf("done\n");
  fclose(resolv);
  /*rename("/etc/resolv.conf","/etc/resolv.confSAVE"); */
}

int isBlacklisted(char *nameBuf) {
  int i;
  for (i=0;i < BlacklistArraySize;i++) {
    if (strstr(nameBuf,BlacklistArray[i])) return 1;
  }
  return 0;
  
/*IMPORTANT: THE IP ADDRESSES 64.27.117.29 AND 63.251.179.49 */	
/*MEAN 'NOT FOUND'; THEY ARE PHONY 'WEBSEARCH' PAGES */
/*LOOK FOR THOSE NUMBERS IN ANSWERS, AND BLACKLIST THEM*/

/* This cloudfront thing is a new tracking threat: I need some of them,
   but definitely not all of them.
*/
  if (strstr(nameBuf,"cloudfront")) {
    if (strstr(nameBuf,"dctkfvs9istwk")) return 0;
    else if (strstr(nameBuf,"d2p4ir3ro")) return 0;
    else return 1;
  }
  return 0;
}

int isIPBlacklisted(int bytesRead) {
  int x;
  for (x = 12;x < bytesRead;x++) {
    if (buf[x] == 0 && buf[x+1] == 4) /* 4 bytes of data, maybe */ {
      if (buf[x+2] == 198 && buf[x+3] == 105 & buf[x+4] == 254 && x[buf+5] == 64) {
        return TRUE;
      }
    }
  }
  for (x = 12;x < bytesRead;x++) {
    if (buf[x] == 0 && buf[x+1] == 4) /* 4 bytes of data, maybe */ {
      if (buf[x+2] == 198 && buf[x+3] == 105 & buf[x+4] == 244 && x[buf+5] == 64) {
        return TRUE;
      }
    }
  }
  return FALSE;
}

void displayIncomingRequest(int readCount) {
  int x;
  HEADER dnsHeader;
  for (x=0;x < 12;x++) {
    displayChar(buf[x]);
  }
  printf("\n");
  for (x=12;x < readCount;x++) {
    displayChar(buf[x]);
  }
  printf("\n");
  memcpy(&dnsHeader,buf,12);             
  displayHeaderReceived(dnsHeader);
}

/* debugging function */
int displayHeaderReceived(HEADER dnsHeader)
{
  printf("dns header:\n");
  printf("id = %d\n",dnsHeader.id);
  printf("qr=%d ",dnsHeader.qr);
  if (dnsHeader.qr == 1) printf("(response)\n");
  else printf("(query)\n");
  printf("opcode=%d ",dnsHeader.opcode);
  if (dnsHeader.opcode == 0) printf("(standard query)\n");
  else if (dnsHeader.opcode == 1) printf("(nverse query)\n");
  else if (dnsHeader.opcode == 2) printf("(server status request)\n");
  printf("rd=%d ",dnsHeader.rd);
  if (dnsHeader.rd == 0) printf("(recursion not desired)\n");
  else printf("(recursion desired)\n");
  printf("tc=%d ",dnsHeader.tc);
  if (dnsHeader.tc == 0) printf("(not truncated)\n");
  else printf("(truncated)\n");
  printf("aa=%d ",dnsHeader.aa);
  if (dnsHeader.aa == 0) printf("(not authoritative)\n");
  else printf("(authoritative)\n");
  printf("ra=%d ",dnsHeader.ra);
  if (dnsHeader.ra == 0) printf("(recursion not available)\n");
  else printf("(recursion available)\n");
  printf("rcode=%d ",dnsHeader.rcode);
  if (dnsHeader.rcode == 0) printf("(no error)\n");
  else printf("(error %d)\n",dnsHeader.rcode);
/*
rcode values returned:
0 no error
1 format error
2 server failure
3 name error - means it doesn't exist
4 not implemented - the query type not supported by the server
5 refused - like a zone transfer
6 ? a name exists when it should not
7 ? a resource record set exists that should not
8 ? a resource record set that should exist does not
9 not auth - the server receiving the query is not authoritative
10 a name specified in the message is not within the zone specified in the message.

set the answer count = 0 to indicate no answer
type 28 is an ipv6, type 12 is reverse ipv6
*/  
  printf("n questions = %d\n",buf[5] + buf[4] * 256);
}

int extractRequestData(char *nameBuf,int* class,int *type) {
  int x,y,requestPtr;
  char *request = buf + sizeof(HEADER);
  requestPtr = 0;y = 0;
  while (request[requestPtr]) {
    for (x = requestPtr;x < requestPtr + request[requestPtr];x++) {
      nameBuf[y++] = request[x+1];
      if (x > 63) { 
        printf("name parse error: ");
        nameBuf[y] = 0;
        printf("%s\n", nameBuf);
        return 1; 
      }
    }
    requestPtr += (request[requestPtr] + 1);
    if (requestPtr > 255) { 
      printf("Name parse error: ");
      printf("%s\n", nameBuf);
      return 1; 
    }
    if (request[requestPtr]) nameBuf[y++] = '.';
    else nameBuf[y] = 0;
  }
  requestPtr ++;
  unsigned short *request_data = (unsigned short *)&(request[requestPtr]);
  *type = ntohs(request_data[0]);
  *class = ntohs(request_data[1]);
  return 0;
}

int openTCP53()
{
  int skfd,connectSock;
  struct sockaddr_in sockAddress,*sockPtr;
  int sinlen = sizeof(sockAddress);

  skfd = socket(AF_INET,SOCK_STREAM,0); 
  memset(&sockAddress, 0, sizeof(sockAddress));
  sockAddress.sin_family = AF_INET;
  sockAddress.sin_addr.s_addr = INADDR_ANY;
  sockAddress.sin_port = htons(53);
  if (bind(skfd, (struct sockaddr*)&sockAddress, sizeof(sockAddress)) < 0)
  {
    perror("bind"); exit(0);
  }
  if (listen(skfd,1)<0) { perror("listen");exit(0); }
  while (1)
  {
    connectSock = accept(skfd, (struct sockaddr*)&sockAddress, &sinlen);
    if (connectSock < 0) 
    {
      perror("accept"); exit(0);
    }
    printf("=============incoming port = %d\n",ntohs(sockAddress.sin_port));
    printf("=============incoming addr = %8x\n",sockAddress.sin_addr.s_addr); 
  }  
}

int readBlacklist() {
  unsigned char filebuf[FILEBUFSIZE], *bufPtr;
  FILE *blacklist = fopen("./dnsblock_blacklist.txt","r");
  int k;
  if (blacklist == NULL) {
    perror("Error opening the blacklist");
    exit(1);
  }
  
  bufPtr = fgets(filebuf,FILEBUFSIZE,blacklist);
  
  while (bufPtr) {
    for (k = 0;k < FILEBUFSIZE;k++) {
      if (filebuf[k] == '\n') { filebuf[k] = '\0';break; }
      if (filebuf[k] < ' ') { filebuf[k] = '\0'; }
      filebuf[k] &= 0x7f;
    }
    bufPtr[FILEBUFSIZE - 1] = '\0';
    BlacklistArray[BlacklistArraySize++] = strdup(bufPtr);
    if (BlacklistArraySize >= MAX_BLACKLIST_SIZE) exit(1);
    bufPtr = fgets(filebuf,FILEBUFSIZE,blacklist);
  }
  fclose(blacklist);
}

int main (int argc,char **argv)
{
  int dnsRemoteSocket=0;
  struct sockaddr_in dnsRemoteSockAddress;
  int dnsLocalSocket,readCount,x,y,ptr,bytesRead,blacklisted;
  struct sockaddr_in dnsLocalSockAddress;
  char nameBuf[256],*realDNS;
  int sinlen = sizeof(dnsLocalSockAddress);
  HEADER dnsHeader;
  int type,class,i=0,ret;
  pid_t pid;
  unsigned char* bufPtr;
  fd_set readfd,writefd;
  unsigned short int ids[16],ports[16],portsPtr = 0;

  initLoopback();
  readBlacklist();

  for (x = 0;x < 16;x++) {
    ports[x] = 0; ids[x] = 0;
  }

  if (argc > 1) {
    realDNS = argv[1];
  } else {
    realDNS = REAL_DNS;
  }
  FD_ZERO(&readfd);

  /*
  pid = fork();
  if (pid == 0) openTCP53();
  */
  dnsRemoteSocket = socket(PF_INET, SOCK_DGRAM, 0);
  memset(&dnsRemoteSockAddress, 0, sizeof(dnsRemoteSockAddress));
  dnsRemoteSockAddress.sin_family = AF_INET;
  dnsRemoteSockAddress.sin_addr.s_addr = htons(0);
  dnsRemoteSockAddress.sin_port = htons(14902);
  if (bind(dnsRemoteSocket, (struct sockaddr*)&dnsRemoteSockAddress, sizeof(dnsRemoteSockAddress)) < 0)
  {
    perror("bind"); exit(0);
  }

  dnsRemoteSockAddress.sin_addr.s_addr = inet_addr(realDNS);
  dnsRemoteSockAddress.sin_port = htons(53);
  
  dnsLocalSocket = socket(PF_INET, SOCK_DGRAM, 0);
  memset(&dnsLocalSockAddress, 0, sizeof(dnsLocalSockAddress));
  dnsLocalSockAddress.sin_family = AF_INET;
  dnsLocalSockAddress.sin_addr.s_addr = inet_addr("127.0.0.1");
  dnsLocalSockAddress.sin_port = htons(14901);
  if (bind(dnsLocalSocket, (struct sockaddr*)&dnsLocalSockAddress, sizeof(dnsLocalSockAddress)) < 0)
  {
    perror("bind"); exit(0);
  }
  
  int max_fd = dnsRemoteSocket;
  if (dnsLocalSocket > max_fd) { max_fd = dnsLocalSocket; }  

  printf("USING %s as the dns server\n",realDNS);

  /*TODO: find the real dns server to forward requests to */
  readResolvConf();

  while (1) {
    FD_SET(dnsRemoteSocket,&readfd);
    FD_SET(dnsLocalSocket,&readfd);
    
    ret = select(max_fd+1,&readfd,NULL,NULL,NULL);

    if (FD_ISSET(dnsRemoteSocket,&readfd)) {
      bytesRead = recvfrom(dnsRemoteSocket,buf,BUFSIZE,0,(struct sockaddr *)&dnsRemoteSockAddress,&sinlen);
      memcpy(&dnsHeader,buf,12);

      if (DISPLAY) {
        printf("this is the answer from the upstream dns server:\n");
        displayAnswer(bytesRead);
      }
      /*now the answer may contain a blacklisted IP address, check */
      /*for that */
      if (isIPBlacklisted(bytesRead)) {
        printf("IP BLACKLISTED\n");
        dnsHeader.qr = 1; /* response */
        dnsHeader.aa = 1; /* authoritative */
        dnsHeader.ra = 1; /*recursion avail */
        dnsHeader.rcode = 3; /* NXDOMAIN */
      
        memcpy(buf,&dnsHeader,12);
        buf[7] = 0;  /* no answer */
        buf[9] = 0;  /* no authority; who you gonna believe? */
        buf[11] = 0; /* how much info do you want, anyway?*/
      }
      for (x = 0;x < 16;x++) {
        if (ids[x+portsPtr & 0xf] == ntohs(dnsHeader.id)) {
          dnsLocalSockAddress.sin_port = ports[x+portsPtr & 0xf];
          sendto(dnsLocalSocket,buf,bytesRead,0,(struct sockaddr *)&dnsLocalSockAddress,sinlen);
          break;
        }
        /* if we can't find a port to return this to, just drop it */
      }
    }
    if (FD_ISSET(dnsLocalSocket,&readfd)) {
      readCount = recvfrom(dnsLocalSocket,buf,BUFSIZE,0,(struct sockaddr *)&dnsLocalSockAddress,&sinlen);  
      memcpy(&dnsHeader,buf,12);
      if (readCount < 0) perror("recvfrom");

      /* responses don't necessarily come back in the order we sent them, so 
         remember packet ids, and the port numbers to return them to:
      */
      portsPtr--;portsPtr &= 0xf;
      ids[portsPtr] = ntohs(dnsHeader.id);
      ports[portsPtr] = dnsLocalSockAddress.sin_port; 
      
      if (DISPLAY) displayIncomingRequest(readCount);
  
      if (extractRequestData(nameBuf,&class,&type)) {
        continue;  /* some format error with this request, drop it */
      }

      if (1) {
        printf("receive:");
        printf("type: %d ", type);
        if (type == 1) printf("(ipv4 address) ");
        else if (type == 5) printf("(canonical name) ");
        else if (type == 12) printf("(reverse lookup) ");
        else if (type == 15) printf("(mx record) ");
        else if (type == 28) printf("(ipv6 address) ");
        printf(" class: %d nBytes:%d: %s\n",class,readCount,nameBuf);
        fflush(stdout);
      }      
  
      /*at this point, we match the string against our blacklist */
      blacklisted = FALSE;
      if ((type == 1 || type == 28 || type == 15) && isBlacklisted(nameBuf)) {
        blacklisted = TRUE;
      }

      if (blacklisted == FALSE) {    
        if (sendto(dnsRemoteSocket,buf,readCount,0,(struct sockaddr *)&dnsRemoteSockAddress,sinlen) < 0) {
	  perror("sendto");
	}
	continue;
      }

      /* ok, this is blacklisted */
      printf("*****************************\n");
  
      ptr += 1;  /* move past the class */
      dnsHeader.qr = 1; /* response */
      dnsHeader.aa = 1; /* authoritative */
      dnsHeader.ra = 1; /*recursion avail */
      dnsHeader.rcode = 3;
      
      memcpy(buf,&dnsHeader,12);
      buf[7] = 0;  /* no answer */
      buf[9] = 0;  /* no authority; who you gonna believe? */
      buf[11] = 0; /* how much info do you want, anyway?*/

      /* now send our answer back */
      printf("returning answer to %d\n", ntohs(dnsLocalSockAddress.sin_port));
      sendto(dnsLocalSocket,buf,ptr,0,(struct sockaddr *)&dnsLocalSockAddress,sinlen);
    }
  }
  exit(0);
}
