#include "CFSafety.h"
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#ifdef __APPLE__
#include <sys/acl.h>
#endif

static int no_grant_acl(int fd) {
#ifdef __APPLE__
 errno=0;acl_t acl=acl_get_fd_np(fd,ACL_TYPE_EXTENDED);
 if(!acl)return errno==ENOENT;
 acl_entry_t entry;int selector=ACL_FIRST_ENTRY,valid=1;
 for(;;){
  errno=0;int result=acl_get_entry(acl,selector,&entry);
  if(result==-1&&errno==EINVAL)break;
  if(result!=0){valid=0;break;}
  acl_tag_t tag;
  if(acl_get_tag_type(entry,&tag)||tag!=ACL_EXTENDED_DENY){valid=0;break;}
  selector=ACL_NEXT_ENTRY;
 }
 acl_free(acl);return valid;
#else
 return 0;
#endif
}

/* Read-only trust check. A deny ACL cannot grant a non-root writer access. */
int as_root_configuration_descriptor(int fd,int directory) {
 if(directory!=0&&directory!=1)return 0;
 struct stat s;if(fstat(fd,&s)||s.st_uid!=0)return 0;
 if(directory){if(!S_ISDIR(s.st_mode)||(s.st_mode&0022))return 0;}
 else if(!S_ISREG(s.st_mode)||s.st_nlink!=1||((s.st_mode&07777)!=0644&&(s.st_mode&07777)!=0444)||s.st_size<=0||s.st_size>65536)return 0;
 return no_grant_acl(fd);
}

int as_no_grant_acl_descriptor(int fd) { return no_grant_acl(fd); }

int as_unshared_node_descriptor(int fd,uint32_t owner) {
 struct stat s;if(fstat(fd,&s)||s.st_uid!=owner||(!S_ISDIR(s.st_mode)&&!S_ISREG(s.st_mode))||(s.st_mode&0022))return 0;
 return no_grant_acl(fd);
}
