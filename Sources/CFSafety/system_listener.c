#include "CFSafety.h"
#include <errno.h>
#include <unistd.h>
#ifdef __APPLE__
#include <launch.h>
#include <libproc.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static const char service_path[]="/Library/Application Support/App Sweep/Service/control.sock";
int as_unix_stream_listener(int fd) {
 struct socket_fdinfo info;memset(&info,0,sizeof(info));
 if(fd<0||proc_pidfdinfo(getpid(),fd,PROC_PIDFDSOCKETINFO,&info,sizeof(info))!=(int)sizeof(info)||
    info.psi.soi_family!=AF_UNIX||info.psi.soi_type!=SOCK_STREAM||info.psi.soi_kind!=SOCKINFO_UN||
    !(info.psi.soi_options&SO_ACCEPTCONN))return 0;
 struct sockaddr_un address; socklen_t size=sizeof(address);
 memset(&address,0,sizeof(address));
 if(getsockname(fd,(struct sockaddr *)&address,&size)||address.sun_family!=AF_UNIX||
    size<=offsetof(struct sockaddr_un,sun_path)||size>sizeof(address)||
    !address.sun_path[0]||strnlen(address.sun_path,sizeof(address.sun_path))==sizeof(address.sun_path))return 0;
 return 1;
}
static int listener_valid(int fd) {
 struct stat metadata;
 /* launchd binds privately then renames the socket. getsockname retains the
  * old kernel name, so it cannot attest the published filesystem path. The
  * sole activation FD comes from launchd's fixed Control entry; separately
  * verify kernel listener state and the fixed root-owned published endpoint.
  * Installation still requires the actual peer's pinned code and challenge. */
 if(!as_unix_stream_listener(fd)||lstat(service_path,&metadata)||!S_ISSOCK(metadata.st_mode)||metadata.st_uid!=0||metadata.st_nlink!=1||
    (metadata.st_mode&07777)!=0666)return 0;
 return 1;
}
int as_activate_system_listener(void) {
 if(getuid()!=0||geteuid()!=0){errno=EPERM;return -1;}
 int *fds=NULL;size_t count=0;int result=launch_activate_socket("Control",&fds,&count);
 if(result||count!=1||!fds){if(fds){for(size_t i=0;i<count;i++)close(fds[i]);free(fds);}errno=result?result:EINVAL;return -1;}
 int fd=fds[0];free(fds);
 int flags=fcntl(fd,F_GETFL);
 if(!listener_valid(fd)||flags<0||fcntl(fd,F_SETFL,flags|O_NONBLOCK)||fcntl(fd,F_SETFD,FD_CLOEXEC)){
  close(fd);errno=EPERM;return -1;
 }
 return fd;
}
int as_accept_system_peer(int fd,int timeout_ms) {
 if(getuid()!=0||geteuid()!=0||timeout_ms<1||timeout_ms>10000||!listener_valid(fd)){errno=EPERM;return -1;}
 struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))return -1;
 int64_t deadline=(int64_t)t.tv_sec*1000+t.tv_nsec/1000000+timeout_ms;
 for(;;){
  if(clock_gettime(CLOCK_MONOTONIC,&t))return -1;
  int64_t now=(int64_t)t.tv_sec*1000+t.tv_nsec/1000000;
  if(now>=deadline){errno=ETIMEDOUT;return -2;}
  struct pollfd ready={.fd=fd,.events=POLLIN};int result=poll(&ready,1,(int)(deadline-now));
  if(result<0&&errno==EINTR)continue;
  if(result==0){errno=ETIMEDOUT;return -2;}
  if(result<0||!(ready.revents&POLLIN)){errno=EIO;return -1;}
  int connected=accept(fd,NULL,NULL);
  if(connected<0&&(errno==EINTR||errno==EAGAIN||errno==EWOULDBLOCK))continue;
  if(connected<0)return -1;
  int flags=fcntl(connected,F_GETFL);
  if(flags<0||fcntl(connected,F_SETFL,flags|O_NONBLOCK)||fcntl(connected,F_SETFD,FD_CLOEXEC)){close(connected);return -1;}
  return connected;
 }
}
#else
int as_unix_stream_listener(int fd){(void)fd;errno=ENOTSUP;return 0;}
int as_activate_system_listener(void){errno=ENOTSUP;return -1;}
int as_accept_system_peer(int fd,int timeout_ms){(void)fd;(void)timeout_ms;errno=ENOTSUP;return -1;}
#endif
