#define _GNU_SOURCE
#include "CFSafety.h"
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/file.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <dirent.h>
#include <stdatomic.h>
#include <pwd.h>
#include <limits.h>
#ifdef __APPLE__
#include <sys/acl.h>
#include <sys/xattr.h>
#include <sys/attr.h>
#include <uuid/uuid.h>
#endif
#ifdef __linux__
#include <sys/syscall.h>
#include <linux/fs.h>
#endif
static int simple(const char *n) { return n && *n && !strchr(n,'/') && strcmp(n,".") && strcmp(n,".."); }
static int same(const ASIdentity *,const ASIdentity *);
static void identity(const struct stat *s, ASIdentity *o) {
 memset(o,0,sizeof(*o)); o->device=s->st_dev; o->inode=s->st_ino; o->links=s->st_nlink; o->mode=s->st_mode; o->owner=s->st_uid; o->size=s->st_size;
#ifdef __APPLE__
 o->modified_seconds=s->st_mtimespec.tv_sec; o->modified_nanoseconds=s->st_mtimespec.tv_nsec;
 o->changed_seconds=s->st_ctimespec.tv_sec; o->changed_nanoseconds=s->st_ctimespec.tv_nsec;
#else
 o->modified_seconds=s->st_mtim.tv_sec; o->modified_nanoseconds=s->st_mtim.tv_nsec;
 o->changed_seconds=s->st_ctim.tv_sec; o->changed_nanoseconds=s->st_ctim.tv_nsec;
#endif
}
int as_open_directory(const char *path) {
 if (!path || path[0]!='/') { errno=EINVAL; return -1; }
 int fd=open("/",O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW); if(fd<0)return -1;
 char *copy=strdup(path+1); if(!copy){close(fd);return -1;}
 char *save=NULL; char *p=strtok_r(copy,"/",&save);
 while(p) { if(!simple(p)){close(fd);free(copy);errno=EINVAL;return -1;}
  int next=openat(fd,p,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW); if(next<0){int e=errno;close(fd);free(copy);errno=e;return -1;}
  close(fd);fd=next;p=strtok_r(NULL,"/",&save);
 }
 free(copy);return fd;
}
static int volume_identity(int fd,const char *name,ASIdentity *out) {
#ifdef __APPLE__
 struct attrlist attributes={0};attributes.bitmapcount=ATTR_BIT_MAP_COUNT;attributes.volattr=ATTR_VOL_INFO|ATTR_VOL_UUID;
 struct {uint32_t length;uuid_t uuid;} value={0};
 int result=name?getattrlistat(fd,name,&attributes,&value,sizeof(value),FSOPT_NOFOLLOW):fgetattrlist(fd,&attributes,&value,sizeof(value),0);
 if(result||value.length!=sizeof(value)||uuid_is_null(value.uuid)){if(!result)errno=ENOTSUP;return -1;}
 uuid_unparse_upper(value.uuid,out->volume_uuid);
#else
 (void)fd;(void)name;(void)out;
#endif
 return 0;
}
int as_identity_at(int fd,const char *name,ASIdentity *out) {
 if(!simple(name)){errno=EINVAL;return -1;}struct stat s,after;ASIdentity verified;
 if(fstatat(fd,name,&s,AT_SYMLINK_NOFOLLOW))return -1;identity(&s,out);
 if(volume_identity(fd,name,out)||fstatat(fd,name,&after,AT_SYMLINK_NOFOLLOW))return -1;identity(&after,&verified);
 if(!same(out,&verified)){errno=ESTALE;return -1;}return 0;
}
int as_identity_fd(int fd,ASIdentity *out) {
 struct stat s,after;ASIdentity verified;if(fstat(fd,&s))return -1;identity(&s,out);
 if(volume_identity(fd,NULL,out)||fstat(fd,&after))return -1;identity(&after,&verified);
 if(!same(out,&verified)){errno=ESTALE;return -1;}return 0;
}
int as_installation_entries(int fd,void *output,size_t capacity,size_t *count,size_t *visited) {
 if(!output||!count||!visited||capacity>2*1024*1024){errno=EINVAL;return -1;}
 int scan=openat(fd,".",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(scan<0)return -1;
 DIR *directory=fdopendir(scan);if(!directory){close(scan);return -1;}
 size_t used=0,seen=0;int result=0;struct dirent *entry;
 for(;;){
  errno=0;entry=readdir(directory);if(!entry){if(errno)result=-1;break;}
  const char *name=entry->d_name;if(!strcmp(name,".")||!strcmp(name,".."))continue;
  if(++seen>20000){errno=E2BIG;result=-1;break;}
  size_t length=strlen(name);
  int bundle=(length>=4&&!strcmp(name+length-4,".app"))||(length>=4&&!strcmp(name+length-4,".xpc"))||(length>=6&&!strcmp(name+length-6,".appex"));
  // Only known regular resource files can be skipped. Directories, links,
  // unknown types and bundle-looking names still receive no-follow checks.
  if(entry->d_type==DT_REG&&!bundle)continue;
  if(length+1>capacity-used){errno=E2BIG;result=-1;break;}
  memcpy((char*)output+used,name,length+1);used+=length+1;
 }
 int saved=errno;closedir(directory);if(result){errno=saved;return -1;}
 *count=used;*visited=seen;return 0;
}
int as_is_directory(const ASIdentity *s){return S_ISDIR(s->mode);}
int as_directory_entries(int fd,void *output,size_t capacity,size_t maximum,size_t *count) {
 if(!output||!count||!maximum||maximum>100000||!capacity||capacity>16*1024*1024){errno=EINVAL;return -1;}
 int scan=openat(fd,".",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(scan<0)return -1;
 DIR *directory=fdopendir(scan);if(!directory){close(scan);return -1;}
 size_t used=0,seen=0;int result=0;struct dirent *entry;
 for(;;) {
  errno=0;entry=readdir(directory);if(!entry){if(errno)result=-1;break;}
  const char *name=entry->d_name;if(!strcmp(name,".")||!strcmp(name,".."))continue;
  size_t length=strlen(name);
  if(++seen>maximum||length+1>capacity-used){errno=E2BIG;result=-1;break;}
  memcpy((char*)output+used,name,length+1);used+=length+1;
 }
 int saved=errno;closedir(directory);if(result){errno=saved;return -1;}*count=used;return 0;
}
int as_is_regular(const ASIdentity *s){return S_ISREG(s->mode);}
int as_is_link(const ASIdentity *s){return S_ISLNK(s->mode);}
int as_private_descriptor(int fd) {
 struct stat s;if(fstat(fd,&s)||s.st_uid!=geteuid()||(s.st_mode&077)||(!S_ISDIR(s.st_mode)&&!S_ISREG(s.st_mode)))return 0;
#ifdef __APPLE__
 errno=0;acl_t acl=acl_get_fd_np(fd,ACL_TYPE_EXTENDED);
 // With a valid open descriptor Darwin reports an absent ACL as ENOENT.
 if(!acl)return errno==ENOENT;
 acl_entry_t entry;errno=0;int result=acl_get_entry(acl,ACL_FIRST_ENTRY,&entry);int error=errno;
 acl_free(acl);
 // Darwin returns0 for an entry, -1/EINVAL for an empty valid ACL.
 // All extended ACLs are conservatively retained, including inherited entries.
 if(result!=-1||error!=EINVAL)return 0;
#endif
 return 1;
}
int as_private_directory(int parent,const char *name) {
 if(!simple(name)){errno=EINVAL;return -1;}
 if(mkdirat(parent,name,0700) && errno!=EEXIST)return -1;
 int fd=openat(parent,name,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);if(fd<0)return -1;
 if(!as_private_descriptor(fd)){close(fd);errno=EPERM;return -1;}return fd;
}
static int same(const ASIdentity *a,const ASIdentity *b) { return a->device==b->device&&(!a->volume_uuid[0]||!b->volume_uuid[0]||!strcmp(a->volume_uuid,b->volume_uuid))&&a->inode==b->inode&&a->mode==b->mode&&a->owner==b->owner&&a->links==b->links&&a->size==b->size&&a->modified_seconds==b->modified_seconds&&a->modified_nanoseconds==b->modified_nanoseconds&&a->changed_seconds==b->changed_seconds&&a->changed_nanoseconds==b->changed_nanoseconds; }
static int rename_exclusive(int from,const char *name,int to,const char *dest) {
#ifdef __APPLE__
 return renameatx_np(from,name,to,dest,RENAME_EXCL);
#else
 return (int)syscall(SYS_renameat2,from,name,to,dest,RENAME_NOREPLACE);
#endif
}
int as_move_exclusive(int source,const char *name,int target,const char *dest,const ASIdentity *expected) {
 ASIdentity found,dir; if(!simple(name)||!simple(dest)){errno=EINVAL;return -1;}
 if(as_identity_at(source,name,&found)||!same(&found,expected)||as_identity_fd(target,&dir)){errno=ESTALE;return -1;}
 if(found.device!=dir.device||as_is_link(&found)||(as_is_regular(&found)&&found.links!=1)){errno=EPERM;return -1;}
 if(rename_exclusive(source,name,target,dest))return -1;
 // A failed sync is an indeterminate commit; caller resolves it from both locations.
 if(fsync(source)||fsync(target))return -2;
 return 0;
}
int as_link_private_regular(int source,const char *name,int target,const char *dest,const ASIdentity *expected) {
 ASIdentity current,target_dir;
 if(!simple(name)||!simple(dest)||!expected||!as_is_regular(expected)||expected->owner!=geteuid()||expected->links<1||!as_private_descriptor(source)||!as_private_descriptor(target)||as_identity_fd(target,&target_dir)||target_dir.device!=expected->device){errno=EPERM;return -1;}
 int fd=openat(source,name,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);if(fd<0)return -1;
 if(as_identity_fd(fd,&current)||!same(&current,expected)){close(fd);errno=ESTALE;return -1;}
 if(linkat(source,name,target,dest,0)){int e=errno;close(fd);errno=e;return -1;}
 ASIdentity after,entry,original;
 int valid=!as_identity_fd(fd,&after)&&after.device==current.device&&after.inode==current.inode&&after.owner==current.owner&&after.mode==current.mode&&after.size==current.size&&after.modified_seconds==current.modified_seconds&&after.modified_nanoseconds==current.modified_nanoseconds&&after.links==current.links+1&&!as_identity_at(target,dest,&entry)&&same(&after,&entry)&&!as_identity_at(source,name,&original)&&same(&after,&original);
 close(fd);
 if(!valid){errno=ESTALE;return -2;}
 if(fsync(source)||fsync(target))return -2;
 return 0;
}
int as_write_atomic(int dir,const char *name,const void *data,size_t count) {
 if(!simple(name)||!as_private_descriptor(dir)){errno=EPERM;return -1;}
 ASIdentity old; if(!as_identity_at(dir,name,&old)) { if(!as_is_regular(&old)||old.links!=1||old.owner!=geteuid()||(old.mode&077)){errno=EPERM;return -1;} } else if(errno!=ENOENT)return -1;
 if(!as_identity_at(dir,name,&old)) {
  int existing=openat(dir,name,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);ASIdentity actual;
  if(existing<0)return -1;int valid=as_private_descriptor(existing)&&!as_identity_fd(existing,&actual)&&same(&old,&actual);close(existing);
  if(!valid){errno=EPERM;return -1;}
 }
 static atomic_ulong sequence; char tmp[96];snprintf(tmp,sizeof(tmp),".journal-%ld-%lu",(long)getpid(),atomic_fetch_add_explicit(&sequence,1,memory_order_relaxed)+1);
 int fd=openat(dir,tmp,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);if(fd<0)return -1;
 if(!as_private_descriptor(fd)){close(fd);unlinkat(dir,tmp,0);errno=EPERM;return -1;}
 const char *p=data;size_t done=0;int err=0;
 while(done<count){ssize_t n=write(fd,p+done,count-done);if(n<0&&errno==EINTR)continue;if(n<=0){err=1;break;}done+=(size_t)n;}
 if(!err&&fsync(fd))err=1;
#ifdef __APPLE__
 if(!err&&fcntl(fd,F_FULLFSYNC))err=1;
#endif
 int e=errno;close(fd);
 if(!err&&renameat(dir,tmp,dir,name)){err=1;e=errno;}
 if(!err&&fsync(dir)){err=1;e=errno;}
 if(err)unlinkat(dir,tmp,0);errno=e;return err?-1:0;
}
int as_read_verified_file(int dir,const char *name,const ASIdentity *expected,void *data,size_t capacity,size_t *count) {
 if(!simple(name)||!expected||!as_is_regular(expected)||expected->links!=1||expected->size<0||(uint64_t)expected->size>capacity){errno=EINVAL;return -1;}
 int fd=openat(dir,name,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);if(fd<0)return -1;
 ASIdentity found;if(as_identity_fd(fd,&found)||!same(&found,expected)){close(fd);errno=ESTALE;return -1;}
 size_t total=0;while(total<(size_t)expected->size){ssize_t n=read(fd,(char*)data+total,(size_t)expected->size-total);if(n<0&&errno==EINTR)continue;if(n<=0){close(fd);errno=EIO;return -1;}total+=(size_t)n;}
 char extra;ssize_t end;do{end=read(fd,&extra,1);}while(end<0&&errno==EINTR);
 ASIdentity after,entry;int valid=end==0&&!as_identity_fd(fd,&after)&&same(&after,expected)&&!as_identity_at(dir,name,&entry)&&same(&entry,expected);
 close(fd);if(!valid){errno=ESTALE;return -1;}*count=total;return 0;
}
int as_cache_node_metadata_with_flags(int dir,const char *name,const ASIdentity *expected,uint32_t *group,uint32_t *flags,void *attributes,size_t capacity,size_t *count) {
#ifdef __APPLE__
 if(!simple(name)||!expected||!flags||(!as_is_regular(expected)&&!as_is_directory(expected))||(as_is_regular(expected)&&expected->links<1)||expected->owner!=geteuid()||capacity>65536){errno=EINVAL;return -1;}
 unsigned mode=expected->mode&07777;
 if(as_is_directory(expected)?(mode!=0700&&mode!=0750&&mode!=0755&&mode!=0770&&mode!=0775):(mode!=0600&&mode!=0644)){errno=EPERM;return -1;}
 int fd=openat(dir,name,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);if(fd<0)return -1;
 ASIdentity actual;struct stat s;int error=0;size_t used=0;
 if(as_identity_fd(fd,&actual)||!same(&actual,expected)||fstat(fd,&s)||(s.st_flags & ~UF_HIDDEN)){error=1;goto finish_metadata;}
 /* A real root service can preserve an existing group on its own object.
  * Ordinary users still need membership; ownership/mode/ACL checks stay above. */
 if((getuid()!=0||geteuid()!=0)&&s.st_gid!=getgid()){
  gid_t groups[256];int n=getgroups(256,groups),member=0;
  if(n<0){error=1;goto finish_metadata;}
  for(int i=0;i<n;i++)if(groups[i]==s.st_gid)member=1;
  if(!member){error=1;goto finish_metadata;}
 }
 errno=0;acl_t acl=acl_get_fd_np(fd,ACL_TYPE_EXTENDED);
 if(acl){acl_entry_t entry;errno=0;int result=acl_get_entry(acl,ACL_FIRST_ENTRY,&entry);int e=errno;acl_free(acl);if(result!=-1||e!=EINVAL){error=1;goto finish_metadata;}}
 else if(errno!=ENOENT){error=1;goto finish_metadata;}
 char names[65536];ssize_t length=flistxattr(fd,names,sizeof(names),0);if(length<0){error=1;goto finish_metadata;}
 for(size_t offset=0;offset<(size_t)length;){
  const char *key=names+offset;const char *end=memchr(key,0,(size_t)length-offset);
  if(!end||end==key||end-key>255){error=1;goto finish_metadata;}size_t key_length=(size_t)(end-key)+1;offset+=key_length;
  if(!strcmp(key,"com.apple.decmpfs")||!strcmp(key,"com.apple.ResourceFork")||!strcmp(key,"com.apple.macl")||!strncmp(key,"com.apple.system.",17)){error=1;goto finish_metadata;}
  ssize_t value_length=fgetxattr(fd,key,NULL,0,0,0);
  if(value_length<0||value_length>65536||key_length+4+(size_t)value_length>capacity-used){error=1;goto finish_metadata;}
  unsigned char *out=(unsigned char*)attributes+used;memcpy(out,key,key_length);used+=key_length;
  for(int i=0;i<4;i++)((unsigned char*)attributes)[used+i]=(unsigned char)((uint32_t)value_length>>(24-i*8));used+=4;
  if(fgetxattr(fd,key,(char*)attributes+used,(size_t)value_length,0,0)!=value_length){error=1;goto finish_metadata;}used+=(size_t)value_length;
 }
 if(as_identity_fd(fd,&actual)||!same(&actual,expected)){error=1;goto finish_metadata;}
 *group=s.st_gid;*flags=s.st_flags;*count=used;
finish_metadata:
 close(fd);if(error){errno=EPERM;return -1;}return 0;
#else
 (void)dir;(void)name;(void)expected;(void)group;(void)flags;(void)attributes;(void)capacity;(void)count;errno=ENOTSUP;return -1;
#endif
}
int as_cache_node_metadata(int dir,const char *name,const ASIdentity *expected,uint32_t *group,void *attributes,size_t capacity,size_t *count) {
 uint32_t flags=0;int result=as_cache_node_metadata_with_flags(dir,name,expected,group,&flags,attributes,capacity,count);
 /* Older archive formats cannot record flags; keep their strict behavior. */
 if(!result&&flags){errno=EPERM;return -1;}return result;
}
int as_cache_file_metadata(int dir,const char *name,const ASIdentity *expected,uint32_t *group,void *attributes,size_t capacity,size_t *count) {
 if(!expected||!as_is_regular(expected)||expected->links!=1){errno=EINVAL;return -1;}
 return as_cache_node_metadata(dir,name,expected,group,attributes,capacity,count);
}
int as_apply_private_node_metadata_with_flags(int fd,const ASIdentity *expected,const ASIdentity *metadata,uint32_t group,uint32_t flags,const void *attributes,size_t attribute_count) {
#ifdef __APPLE__
 ASIdentity actual;
 if(!expected||!metadata||(flags & ~UF_HIDDEN)||!as_private_descriptor(fd)||as_identity_fd(fd,&actual)||!same(&actual,expected)||metadata->owner!=geteuid()||attribute_count>65536||(attribute_count&&!attributes)){errno=EPERM;return -1;}
 int directory=as_is_directory(metadata);unsigned mode=metadata->mode&07777;
 if(metadata->modified_nanoseconds<0||metadata->modified_nanoseconds>=1000000000||(directory?(!as_is_directory(&actual)||(mode!=0700&&mode!=0750&&mode!=0755&&mode!=0770&&mode!=0775)):(!as_is_regular(metadata)||!as_is_regular(&actual)||metadata->links!=1||actual.links!=1||actual.size!=metadata->size||(mode!=0600&&mode!=0644)))){errno=EPERM;return -1;}
 const unsigned char *attrs=attributes;
 if(fchown(fd,geteuid(),group))return -1;
 for(size_t offset=0;offset<attribute_count;){
  const char *key=(const char*)attrs+offset;const unsigned char *end=memchr(key,0,attribute_count-offset);
  if(!end||end==(const unsigned char*)key||end-(const unsigned char*)key>255){errno=EINVAL;return -1;}
  offset+=(size_t)(end-(const unsigned char*)key)+1;if(attribute_count-offset<4){errno=EINVAL;return -1;}
  uint32_t length=0;for(int i=0;i<4;i++)length=(length<<8)|attrs[offset+i];offset+=4;
  if(length>attribute_count-offset||!strcmp(key,"com.apple.decmpfs")||!strcmp(key,"com.apple.ResourceFork")||!strcmp(key,"com.apple.macl")||!strncmp(key,"com.apple.system.",17)){errno=EPERM;return -1;}
  if(fsetxattr(fd,key,attrs+offset,length,0,0))return -1;offset+=length;
 }
 struct timespec times[2]={{0,UTIME_OMIT},{metadata->modified_seconds,metadata->modified_nanoseconds}};
 if(fchmod(fd,mode)||fchflags(fd,flags)||futimens(fd,times)||fsync(fd)||(!directory&&fcntl(fd,F_FULLFSYNC)))return -1;
 return 0;
#else
 (void)fd;(void)expected;(void)metadata;(void)group;(void)flags;(void)attributes;(void)attribute_count;errno=ENOTSUP;return -1;
#endif
}
int as_apply_private_node_metadata(int fd,const ASIdentity *expected,const ASIdentity *metadata,uint32_t group,const void *attributes,size_t attribute_count) {
 return as_apply_private_node_metadata_with_flags(fd,expected,metadata,group,0,attributes,attribute_count);
}
int as_write_recovered_regular(int dir,const char *name,const void *data,size_t count,const ASIdentity *metadata,uint32_t group,const void *attributes,size_t attribute_count) {
#ifdef __APPLE__
 if(!simple(name)||!as_private_descriptor(dir)||!metadata||!as_is_regular(metadata)||metadata->owner!=geteuid()||metadata->links!=1||metadata->size<0||(uint64_t)metadata->size!=count||count>16*1024*1024||attribute_count>65536){errno=EPERM;return -1;}
 unsigned mode=metadata->mode&07777;if(mode!=0600&&mode!=0644){errno=EPERM;return -1;}
 static atomic_ulong recovery_sequence;char tmp[96];snprintf(tmp,sizeof(tmp),".rebuild-%ld-%lu",(long)getpid(),atomic_fetch_add_explicit(&recovery_sequence,1,memory_order_relaxed)+1);
 int fd=openat(dir,tmp,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);if(fd<0)return -1;
 int error=0;size_t written=0;const unsigned char *bytes=data,*attrs=attributes;
 while(written<count){ssize_t n=write(fd,bytes+written,count-written);if(n<0&&errno==EINTR)continue;if(n<=0){error=1;break;}written+=(size_t)n;}
 if(!error&&fchown(fd,geteuid(),group))error=1;
 for(size_t offset=0;!error&&offset<attribute_count;){
  const char *key=(const char*)attrs+offset;const unsigned char *end=memchr(key,0,attribute_count-offset);
  if(!end||end==(const unsigned char*)key||end-(const unsigned char*)key>255){error=1;break;}
  offset+=(size_t)(end-(const unsigned char*)key)+1;if(attribute_count-offset<4){error=1;break;}
  uint32_t length=0;for(int i=0;i<4;i++)length=(length<<8)|attrs[offset+i];offset+=4;
  if(length>attribute_count-offset||!strcmp(key,"com.apple.decmpfs")||!strcmp(key,"com.apple.ResourceFork")||!strcmp(key,"com.apple.macl")||!strncmp(key,"com.apple.system.",17)){error=1;break;}
  if(fsetxattr(fd,key,attrs+offset,length,0,0)){error=1;break;}offset+=length;
 }
 struct timespec times[2]={{0,UTIME_OMIT},{metadata->modified_seconds,metadata->modified_nanoseconds}};
 if(!error&&(fchmod(fd,mode)||futimens(fd,times)||fsync(fd)||fcntl(fd,F_FULLFSYNC)))error=1;
 ASIdentity created={0};if(as_identity_fd(fd,&created))error=1;
 int saved=errno;close(fd);
 if(!error&&rename_exclusive(dir,tmp,dir,name)){error=1;saved=errno;}
 if(!error&&fsync(dir)){errno=EIO;return -2;}
 if(error){ASIdentity entry;if(!as_identity_at(dir,tmp,&entry)&&same(&entry,&created))unlinkat(dir,tmp,0);errno=saved;return -1;}
 return 0;
#else
 (void)dir;(void)name;(void)data;(void)count;(void)metadata;(void)group;(void)attributes;(void)attribute_count;errno=ENOTSUP;return -1;
#endif
}
int as_read_file(int dir,const char *name,void *data,size_t capacity,size_t *count) {
 if(!simple(name)||!as_private_descriptor(dir)){errno=EPERM;return -1;}int fd=openat(dir,name,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);if(fd<0)return -1;
 struct stat s; if(fstat(fd,&s)||!S_ISREG(s.st_mode)||s.st_nlink!=1||!as_private_descriptor(fd)||s.st_size<0||(uint64_t)s.st_size>capacity){close(fd);errno=EPERM;return -1;}
 size_t total=0;while(total<(size_t)s.st_size){ssize_t n=read(fd,(char*)data+total,(size_t)s.st_size-total);if(n<0&&errno==EINTR)continue;if(n<=0){close(fd);errno=EIO;return -1;}total+=n;}close(fd);*count=total;return 0;
}
static int compare_entry(const void *a,const void *b) {
 return strcmp(((const ASVerifiedEntry*)a)->relative,((const ASVerifiedEntry*)b)->relative);
}
static const ASVerifiedEntry *find_entry(const ASVerifiedEntry *contents,size_t count,const char *relative) {
 if(!count)return NULL;
 ASVerifiedEntry key={.relative=relative};return bsearch(&key,contents,count,sizeof(*contents),compare_entry);
}
// Every leaf must be in the pre-reviewed tree. Directory enumeration cannot
// authorize newly arrived objects, even when they live inside the recovery area.
typedef struct { ASVerifiedEntry **references;size_t count; } ASLinkContext;
static int compare_inode_reference(const void *a,const void *b) {
 const ASIdentity *x=&(*(ASVerifiedEntry *const*)a)->identity,*y=&(*(ASVerifiedEntry *const*)b)->identity;
 if(x->device!=y->device)return x->device<y->device?-1:1;
 return x->inode==y->inode?0:(x->inode<y->inode?-1:1);
}
static void update_link_group(ASLinkContext *context,const ASIdentity *identity) {
 size_t lo=0,hi=context->count;
 while(lo<hi){size_t mid=lo+(hi-lo)/2;ASIdentity *found=&context->references[mid]->identity;
  if(found->device<identity->device||(found->device==identity->device&&found->inode<identity->inode))lo=mid+1;else hi=mid;
 }
 for(size_t i=lo;i<context->count;i++){
  ASIdentity *found=&context->references[i]->identity;
  if(found->device!=identity->device||found->inode!=identity->inode)break;
  *found=*identity;
 }
}
static int remove_tree(int dir,const char *name,const ASIdentity *expected,const ASVerifiedEntry *contents,size_t count,const char *prefix,size_t *visited,unsigned depth,ASLinkContext *links) {
 if(depth>128){errno=ELOOP;return -1;}
 ASIdentity now;if(as_identity_at(dir,name,&now)||!same(&now,expected)){errno=ESTALE;return -1;}
 if(as_is_link(&now)){errno=EPERM;return -1;}
 if(as_is_directory(&now)) {
  int fd=openat(dir,name,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(fd<0)return -1;
  ASIdentity opened;if(as_identity_fd(fd,&opened)||!same(&opened,&now)){close(fd);errno=ESTALE;return -1;}
  int duplicate=dup(fd);DIR *entries=fdopendir(duplicate);if(!entries){close(duplicate);close(fd);return -1;}
  struct dirent *entry;int result=0;errno=0;
  while((entry=readdir(entries))) { if(!strcmp(entry->d_name,".")||!strcmp(entry->d_name,".."))continue;
   ASIdentity child;if(as_identity_at(fd,entry->d_name,&child)||child.device!=now.device){result=-1;break;}
   char relative[PATH_MAX];int length=snprintf(relative,sizeof(relative),"%s%s%s",prefix,*prefix?"/":"",entry->d_name);
   if(length<0||(size_t)length>=sizeof(relative)){errno=ENAMETOOLONG;result=-1;break;}
   const ASVerifiedEntry *known=find_entry(contents,count,relative);
   if(!known||!same(&child,&known->identity)){errno=ESTALE;result=-1;break;}
   (*visited)++;
   // Internal app symlinks are removed as links; targets are never accessed.
   if(as_is_link(&child)){if(unlinkat(fd,entry->d_name,0)){result=-1;break;}}
   else if(remove_tree(fd,entry->d_name,&known->identity,contents,count,relative,visited,depth+1,links)){result=-1;break;}
   errno=0;
  }
  if(errno)result=-1;closedir(entries);close(fd);if(result)return -1;
  ASIdentity final;if(as_identity_at(dir,name,&final)||final.device!=now.device||final.inode!=now.inode||final.owner!=now.owner||final.mode!=now.mode){errno=ESTALE;return -1;}
  if(unlinkat(dir,name,AT_REMOVEDIR))return -1;return fsync(dir);
 }
 if(!as_is_regular(&now)||(!links&&now.links!=1)||now.links<1){errno=EPERM;return -1;}
 if(!links){if(unlinkat(dir,name,0))return -1;return fsync(dir);}
 int fd=openat(dir,name,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);if(fd<0)return -1;
 ASIdentity opened,after;
 if(as_identity_fd(fd,&opened)||!same(&opened,&now)){close(fd);errno=ESTALE;return -1;}
 if(unlinkat(dir,name,0)){int e=errno;close(fd);errno=e;return -1;}
 int valid=!as_identity_fd(fd,&after)&&after.device==now.device&&after.inode==now.inode&&after.owner==now.owner&&after.mode==now.mode&&after.size==now.size&&after.modified_seconds==now.modified_seconds&&after.modified_nanoseconds==now.modified_nanoseconds&&after.links==now.links-1;
 close(fd);if(!valid){errno=ESTALE;return -1;}
 update_link_group(links,&after);
 return fsync(dir);
}
static int remove_verified_impl(int dir,const char *name,const ASIdentity *expected,const ASVerifiedEntry *contents,size_t count,int allow_links) {
 if(!simple(name)||!expected||count>1000000||(count&&!contents)||(as_is_regular(expected)&&count)){errno=EINVAL;return -1;}
 if(allow_links==2&&!as_is_directory(expected)){errno=EPERM;return -1;}
 ASVerifiedEntry *sorted=count?malloc(count*sizeof(*sorted)):NULL;
 if(count&&!sorted)return -1;
 if(count)memcpy(sorted,contents,count*sizeof(*sorted));
 for(size_t i=0;i<count;i++) {
  const char *path=sorted[i].relative;
  if(!path||!*path||*path=='/'||strlen(path)>=PATH_MAX||path[strlen(path)-1]=='/'||strstr(path,"//")||sorted[i].identity.device!=expected->device){free(sorted);errno=EINVAL;return -1;}
  const char *part=path;unsigned depth=1;
  while(*part) { const char *slash=strchr(part,'/');size_t n=slash?(size_t)(slash-part):strlen(part);
   if(!n||(n==1&&part[0]=='.')||(n==2&&!strncmp(part,"..",2))||depth>128){free(sorted);errno=EINVAL;return -1;}
   if(!slash)break;part=slash+1;depth++;
  }
 }
 if(count)qsort(sorted,count,sizeof(*sorted),compare_entry);
 for(size_t i=1;i<count;i++)if(!strcmp(sorted[i-1].relative,sorted[i].relative)){free(sorted);errno=EINVAL;return -1;}
 ASLinkContext context={0};
 if(allow_links&&count){context.references=malloc(count*sizeof(*context.references));if(!context.references){free(sorted);return -1;}}
 for(size_t i=0;i<count;i++)if(as_is_regular(&sorted[i].identity)){
  if(!allow_links&&sorted[i].identity.links!=1){free(sorted);errno=EPERM;return -1;}
  if(allow_links)context.references[context.count++]=&sorted[i];
 }
 if(context.count)qsort(context.references,context.count,sizeof(*context.references),compare_inode_reference);
 for(size_t i=0;i<context.count;){
  size_t end=i+1;
  while(end<context.count&&!compare_inode_reference(&context.references[i],&context.references[end]))end++;
  // Mode 2 is used only after Swift verifies a whole signed application.
  // Outside names are never resolved or edited; unlink only the reviewed tree.
  int valid=allow_links==2?context.references[i]->identity.links>=end-i:context.references[i]->identity.links==end-i;
  for(size_t j=i+1;valid&&j<end;j++)valid=same(&context.references[i]->identity,&context.references[j]->identity);
  if(!valid){free(context.references);free(sorted);errno=EPERM;return -1;}i=end;
 }
 if(as_is_regular(expected)&&expected->links!=1){free(context.references);free(sorted);errno=EPERM;return -1;}
 size_t visited=0;int result=remove_tree(dir,name,expected,sorted,count,"",&visited,0,allow_links?&context:NULL);
 free(context.references);
 free(sorted);if(!result&&visited!=count){errno=ESTALE;return -1;}return result;
}
int as_remove_verified(int dir,const char *name,const ASIdentity *expected,const ASVerifiedEntry *contents,size_t count) { return remove_verified_impl(dir,name,expected,contents,count,0); }
int as_remove_verified_contained_links(int dir,const char *name,const ASIdentity *expected,const ASVerifiedEntry *contents,size_t count) { return remove_verified_impl(dir,name,expected,contents,count,1); }
int as_remove_verified_application_links(int dir,const char *name,const ASIdentity *expected,const ASVerifiedEntry *contents,size_t count) { return remove_verified_impl(dir,name,expected,contents,count,2); }
uint64_t as_available_bytes(int fd){struct statvfs s;if(fstatvfs(fd,&s))return 0;return (uint64_t)s.f_bavail*s.f_frsize;}
uint32_t as_current_uid(void){return geteuid();}
int as_account_home_directory(uint32_t uid,char *output,size_t capacity){
 if(!output||!capacity){errno=EINVAL;return -1;}
 struct passwd record,*found=NULL;char buffer[16384];
 int error=getpwuid_r(uid,&record,buffer,sizeof(buffer),&found);
 if(error||!found||found->pw_uid!=uid||!found->pw_dir||found->pw_dir[0]!='/'){errno=error?error:ENOENT;return -1;}
 size_t length=strlen(found->pw_dir);if(length+1>capacity){errno=ERANGE;return -1;}
 memcpy(output,found->pw_dir,length+1);return 0;
}
int as_home_directory(char *output,size_t capacity){return as_account_home_directory(geteuid(),output,capacity);}
int as_lock(int fd){return flock(fd,LOCK_EX|LOCK_NB);}
void as_close(int fd){if(fd>=0)close(fd);}
