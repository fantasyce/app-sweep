#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
int main(int argc,char **argv) {
 if(argc!=2||strlen(argv[1])>=sizeof(((struct sockaddr_un *)0)->sun_path))return 2;
 int fd=socket(AF_UNIX,SOCK_STREAM,0);if(fd<0)return 3;
 if(fcntl(fd,F_SETFD,FD_CLOEXEC)){close(fd);return 4;}
 struct sockaddr_un address;memset(&address,0,sizeof(address));
 address.sun_family=AF_UNIX;address.sun_len=sizeof(address);strcpy(address.sun_path,argv[1]);
 if(connect(fd,(struct sockaddr *)&address,sizeof(address))){close(fd);return 5;}
 char ack=0;int ok=read(fd,&ack,1)==1&&ack=='x';close(fd);return ok?0:6;
}
