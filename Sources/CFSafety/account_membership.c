#include "CFSafety.h"
#ifdef __APPLE__
#include <sys/types.h>
#include <membership.h>
#include <grp.h>
#include <string.h>
#include <limits.h>
#endif

/* A freshly queried directory-service membership, including nested groups.
   Unknown identities and lookup failures never confer administrator authority. */
int as_administrator_member(uint32_t uid) {
#ifdef __APPLE__
 if(uid<500 || uid>=INT32_MAX) return -1;
 struct group record,*found=NULL;char buffer[16384];
 if(getgrnam_r("admin",&record,buffer,sizeof(buffer),&found) || !found ||
    !found->gr_name || strcmp(found->gr_name,"admin")) return -1;
 uuid_t user,group;int member=-1;
 if(mbr_uid_to_uuid((uid_t)uid,user) || mbr_gid_to_uuid(found->gr_gid,group) ||
    mbr_check_membership(user,group,&member) || (member!=0 && member!=1)) return -1;
 return member;
#else
 (void)uid;return -1;
#endif
}
