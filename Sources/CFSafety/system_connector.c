#include "CFSafety.h"
#include <errno.h>
#ifdef __APPLE__
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <time.h>

static const char control_path[]="/Library/Application Support/App Sweep/Service/control.sock";
static int root_socket(struct stat *value) {
 if(lstat(control_path,value))return 0;
 if(S_ISSOCK(value->st_mode)&&value->st_uid==0&&value->st_nlink==1&&
    (value->st_mode&07777)==0666)return 1;
 errno=EPERM;return 0;
}
static int connect_service(int timeout_ms,int root_health) {
 if((root_health ? getuid()!=0 : getuid()==0)||geteuid()!=getuid()||timeout_ms<1||timeout_ms>10000){errno=EPERM;return -1;}
 struct stat before,after;
 if(!root_socket(&before))return -1;
 int fd=socket(AF_UNIX,SOCK_STREAM,0);if(fd<0)return -1;
 int flags=fcntl(fd,F_GETFL);
 if(flags<0||fcntl(fd,F_SETFL,flags|O_NONBLOCK)||fcntl(fd,F_SETFD,FD_CLOEXEC))goto failed;
 struct sockaddr_un address;memset(&address,0,sizeof(address));address.sun_family=AF_UNIX;
 memcpy(address.sun_path,control_path,sizeof(control_path));
 address.sun_len=(unsigned char)(offsetof(struct sockaddr_un,sun_path)+sizeof(control_path));
 int result=connect(fd,(struct sockaddr *)&address,address.sun_len);
 if(result&&errno!=EINPROGRESS&&errno!=EAGAIN)goto failed;
 if(result){
  struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))goto failed;
  int64_t deadline=(int64_t)t.tv_sec*1000+t.tv_nsec/1000000+timeout_ms;
  for(;;){
   if(clock_gettime(CLOCK_MONOTONIC,&t))goto failed;
   int64_t now=(int64_t)t.tv_sec*1000+t.tv_nsec/1000000;
   if(now>=deadline){errno=ETIMEDOUT;goto failed;}
   struct pollfd ready={.fd=fd,.events=POLLOUT};result=poll(&ready,1,(int)(deadline-now));
   if(result<0&&errno==EINTR)continue;
   if(result<=0){if(!result)errno=ETIMEDOUT;goto failed;}
   int error=0;socklen_t size=sizeof(error);
   if(getsockopt(fd,SOL_SOCKET,SO_ERROR,&error,&size)||error||!(ready.revents&POLLOUT)){
    errno=error?error:ECONNREFUSED;goto failed;
   }
   break;
  }
 }
 if(!root_socket(&after))goto failed;
 if(before.st_dev!=after.st_dev||before.st_ino!=after.st_ino){errno=ESTALE;goto failed;}
 return fd;
failed: {
 int saved=errno;close(fd);errno=saved;return -1;
 }
}
int as_connect_system_service(int timeout_ms) { return connect_service(timeout_ms,0); }
int as_connect_system_service_health(int timeout_ms) { return connect_service(timeout_ms,1); }
#else
int as_connect_system_service(int timeout_ms){(void)timeout_ms;errno=ENOTSUP;return -1;}
int as_connect_system_service_health(int timeout_ms){(void)timeout_ms;errno=ENOTSUP;return -1;}
#endif
