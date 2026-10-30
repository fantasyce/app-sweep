#include "CFSafety.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <poll.h>
#include <time.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>

#define AS_CONTROL_MAX 65536
static int64_t control_milliseconds(void) {
 struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))return -1;
 return (int64_t)t.tv_sec*1000+t.tv_nsec/1000000;
}
/* The local socket family remains available after peer close. getpeername can
 * return ENOTCONN on macOS while a complete final frame is still queued. Reading
 * an unconnected AF_UNIX stream still fails in recv; credentials are separately
 * authenticated by the caller and are never inferred from this transport check. */
static int local_stream(int fd) {
 struct sockaddr_storage address;memset(&address,0,sizeof(address));socklen_t length=sizeof(address);
 int type=0;socklen_t type_length=sizeof(type);
 return fd>=0&&!getsockopt(fd,SOL_SOCKET,SO_TYPE,&type,&type_length)&&type==SOCK_STREAM&&
  !getsockname(fd,(struct sockaddr *)&address,&length)&&address.ss_family==AF_UNIX;
}
static int control_ready(int fd,short events,int64_t deadline) {
 for(;;){
  int64_t now=control_milliseconds();if(now<0)return -1;
  if(now>=deadline){errno=ETIMEDOUT;return -2;}
  struct pollfd p={.fd=fd,.events=events,.revents=0};
  int result=poll(&p,1,(int)(deadline-now));
  if(result<0&&errno==EINTR)continue;
  if(result==0){errno=ETIMEDOUT;return -2;}
  if(result<0)return -1;
  if(p.revents&events)return 0;
  errno=ECONNRESET;return -1;
 }
}
int as_wait_control_frame(int fd,int timeout_ms) {
 if(timeout_ms<1||timeout_ms>10000||!local_stream(fd)){errno=EINVAL;return -1;}
 int64_t now=control_milliseconds();if(now<0)return -1;
 return control_ready(fd,POLLIN,now+timeout_ms);
}
static int control_read_exact(int fd,unsigned char *output,size_t count,int64_t deadline) {
 size_t done=0;
 while(done<count){
  int ready=control_ready(fd,POLLIN,deadline);if(ready)return ready;
  ssize_t got=recv(fd,output+done,count-done,MSG_DONTWAIT);
  if(got<0&&(errno==EINTR||errno==EAGAIN||errno==EWOULDBLOCK))continue;
  if(got<=0){if(got==0)errno=ECONNRESET;return -1;}
  done+=(size_t)got;
 }
 return 0;
}
static int control_length(const unsigned char *bytes,size_t *length) {
 if(memcmp(bytes,"ASWP",4)){errno=EINVAL;return -3;}
 uint32_t n=((uint32_t)bytes[4]<<24)|((uint32_t)bytes[5]<<16)|((uint32_t)bytes[6]<<8)|bytes[7];
 if(!n||n>AS_CONTROL_MAX){errno=E2BIG;return -3;}
 *length=8+(size_t)n;return 0;
}
int as_read_control_frame(int fd,void *output,size_t capacity,int timeout_ms,size_t *count) {
 if(!output||!count||capacity<8||capacity>AS_CONTROL_MAX+8||timeout_ms<1||timeout_ms>10000||!local_stream(fd)){errno=EINVAL;return -1;}
 *count=0;int64_t now=control_milliseconds();if(now<0)return -1;int64_t deadline=now+timeout_ms;
 int result=control_read_exact(fd,output,8,deadline);if(result)return result;
 size_t total=0;result=control_length(output,&total);if(result)return result;
 if(total>capacity){errno=E2BIG;return -3;}
 result=control_read_exact(fd,(unsigned char *)output+8,total-8,deadline);if(result)return result;
 *count=total;return 0;
}
int as_write_control_frame(int fd,const void *data,size_t count,int timeout_ms) {
 if(!data||count<8||count>AS_CONTROL_MAX+8||timeout_ms<1||timeout_ms>10000||!local_stream(fd)){errno=EINVAL;return -1;}
 size_t total=0;int result=control_length(data,&total);if(result||total!=count){errno=EINVAL;return -3;}
#ifdef __APPLE__
 int one=1;if(setsockopt(fd,SOL_SOCKET,SO_NOSIGPIPE,&one,sizeof(one)))return -1;
#endif
 int64_t now=control_milliseconds();if(now<0)return -1;int64_t deadline=now+timeout_ms;size_t done=0;
 while(done<count){
  result=control_ready(fd,POLLOUT,deadline);if(result)return result;
  int flags=MSG_DONTWAIT;
#ifdef MSG_NOSIGNAL
  flags|=MSG_NOSIGNAL;
#endif
  ssize_t sent=send(fd,(const unsigned char *)data+done,count-done,flags);
  if(sent<0&&(errno==EINTR||errno==EAGAIN||errno==EWOULDBLOCK))continue;
  if(sent<=0)return -1;
  done+=(size_t)sent;
 }
 return 0;
}
