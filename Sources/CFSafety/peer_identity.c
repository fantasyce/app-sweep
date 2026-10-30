#include "CFSafety.h"
#include <errno.h>
#include <string.h>
#ifdef __APPLE__
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <bsm/libbsm.h>
#endif

int as_peer_identity(int fd, ASPeerIdentity *result) {
 if(!result||fd<0){errno=EINVAL;return -1;}
 memset(result,0,sizeof(*result));
#ifdef __APPLE__
 audit_token_t token; socklen_t length=sizeof(token);
 if(getsockopt(fd,SOL_LOCAL,LOCAL_PEERTOKEN,&token,&length)||length!=sizeof(token)){errno=EPERM;return -1;}
 uid_t uid;gid_t gid;pid_t pid=0;socklen_t pid_length=sizeof(pid);
 if(getpeereid(fd,&uid,&gid)||getsockopt(fd,SOL_LOCAL,LOCAL_PEERPID,&pid,&pid_length)||pid_length!=sizeof(pid)||pid<=0||uid!=audit_token_to_euid(token)||pid!=audit_token_to_pid(token)){errno=EPERM;return -1;}
 _Static_assert(sizeof(token)==32,"Public audit token size changed");
 result->effective_uid=uid;result->real_uid=audit_token_to_ruid(token);result->pid=pid;
 memcpy(result->audit_token,&token,sizeof(token));return 0;
#else
 errno=ENOTSUP;return -1;
#endif
}
