#include "CFSafety.h"
#include <errno.h>
#ifdef __APPLE__
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

static int component(const char *name) {
 return name && *name && !strchr(name,'/') && strcmp(name,".") && strcmp(name,"..");
}
static int equal_identity(const ASIdentity *a,const ASIdentity *b,int after_rename) {
 return a->device==b->device && a->inode==b->inode && a->mode==b->mode &&
  a->owner==b->owner && a->links==b->links && a->size==b->size &&
  a->modified_seconds==b->modified_seconds && a->modified_nanoseconds==b->modified_nanoseconds &&
  (after_rename || (a->changed_seconds==b->changed_seconds && a->changed_nanoseconds==b->changed_nanoseconds));
}
static int owned_directory(const ASIdentity *value,uid_t uid) {
 return as_is_directory(value) && value->owner==uid && !(value->mode&07022);
}
static int parent_still_bound(int fd,const ASIdentity *expected) {
 ASIdentity current;
 return !as_identity_fd(fd,&current) && current.device==expected->device &&
  current.inode==expected->inode && current.mode==expected->mode && current.owner==expected->owner;
}
#endif

int as_exchange_owned_directories(int first,const char *first_name,const ASIdentity *first_object,
 const ASIdentity *first_parent,int second,const char *second_name,const ASIdentity *second_object,
 const ASIdentity *second_parent) {
#ifdef __APPLE__
 uid_t uid=getuid();
 if(!uid || uid!=geteuid() || first<0 || second<0 || !component(first_name) || !component(second_name) ||
    !first_object || !first_parent || !second_object || !second_parent){errno=EINVAL;return -1;}
 ASIdentity ap,bp,a,b;
 if(as_identity_fd(first,&ap) || as_identity_fd(second,&bp) ||
    !equal_identity(&ap,first_parent,0) || !equal_identity(&bp,second_parent,0)){errno=ESTALE;return -1;}
 if(!owned_directory(&ap,uid) || !owned_directory(&bp,uid) ||
    !as_unshared_node_descriptor(first,uid) || !as_private_descriptor(second)){errno=EPERM;return -1;}
 int left=openat(first,first_name,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
 if(left<0)return -1;
 int right=openat(second,second_name,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
 if(right<0){int saved=errno;close(left);errno=saved;return -1;}
 int result=-1,saved=ESTALE;
 if(as_identity_fd(left,&a) || as_identity_fd(right,&b) ||
    !equal_identity(&a,first_object,0) || !equal_identity(&b,second_object,0))goto finish;
 if(!owned_directory(&a,uid) || !owned_directory(&b,uid) ||
    !as_unshared_node_descriptor(left,uid) || !as_unshared_node_descriptor(right,uid)){
  saved=EPERM;goto finish;
 }
 if(a.device!=b.device || a.device!=ap.device || a.device!=bp.device){saved=EXDEV;goto finish;}
 if(a.inode==b.inode || a.inode==ap.inode || a.inode==bp.inode ||
    b.inode==ap.inode || b.inode==bp.inode){saved=EINVAL;goto finish;}
 ASIdentity entry;
 if(as_identity_at(first,first_name,&entry) || !equal_identity(&entry,&a,0) ||
    as_identity_at(second,second_name,&entry) || !equal_identity(&entry,&b,0))goto finish;
 if(renameatx_np(first,first_name,second,second_name,RENAME_SWAP)){
  saved=errno;
  // Do not infer unchanged directory entries after a physical I/O error.
  // The caller must reconcile both positions, including the no-change case.
  if(saved==EIO)result=-2;
  goto finish;
 }
 // Never retry a swap: after this point a failure is an indeterminate commit,
 // even if an observer replaced a name or persistence could not be confirmed.
 result=-2;
 if(fsync(first) || fsync(second)){saved=errno;goto finish;}
 if(!parent_still_bound(first,&ap) || !parent_still_bound(second,&bp) ||
    !as_unshared_node_descriptor(first,uid) || !as_private_descriptor(second) ||
    !as_unshared_node_descriptor(left,uid) || !as_unshared_node_descriptor(right,uid) ||
    as_identity_at(first,first_name,&entry) || !equal_identity(&entry,&b,1) ||
    as_identity_at(second,second_name,&entry) || !equal_identity(&entry,&a,1))goto finish;
 result=0;saved=0;
finish:
 close(left);close(right);errno=saved;return result;
#else
 (void)first;(void)first_name;(void)first_object;(void)first_parent;
 (void)second;(void)second_name;(void)second_object;(void)second_parent;
 errno=ENOTSUP;return -1;
#endif
}
