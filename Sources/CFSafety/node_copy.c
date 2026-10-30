#include "CFSafety.h"
#include <errno.h>
#ifdef __APPLE__
#include <CommonCrypto/CommonDigest.h>
#include <sys/stat.h>
#include <sys/acl.h>
#include <sys/xattr.h>
#include <fcntl.h>
#include <copyfile.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>

#define NODE_META_LIMIT (16U*1024U*1024U)
#define NODE_NAMES_LIMIT 65536U
#define NODE_ACL_LIMIT 65536U
#define NODE_LINK_LIMIT 4096U
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
typedef struct { int64_t deadline; uint64_t maximum; } NodeBudget;
static int64_t milliseconds(void) {
 struct timespec now;if(clock_gettime(CLOCK_MONOTONIC,&now))return -1;
 return (int64_t)now.tv_sec*1000+now.tv_nsec/1000000;
}
static int budget_alive(const NodeBudget *budget) {
 int64_t now=milliseconds();if(now<0)return 0;
 if(now>=budget->deadline){errno=ETIMEDOUT;return 0;}return 1;
}
static int simple_node(const char *name) {
 return name && *name && strlen(name)<=NAME_MAX && !strchr(name,'/') && strcmp(name,".") && strcmp(name,"..");
}
static int identities_equal(const ASIdentity *a,const ASIdentity *b) {
 return a->device==b->device && a->inode==b->inode && a->links==b->links && a->mode==b->mode &&
 a->owner==b->owner && a->size==b->size && a->modified_seconds==b->modified_seconds &&
 a->modified_nanoseconds==b->modified_nanoseconds && a->changed_seconds==b->changed_seconds &&
 a->changed_nanoseconds==b->changed_nanoseconds;
}
static int eligible(const ASIdentity *identity) {
 return identity && identity->owner==getuid() && !(identity->mode&07000) &&
 (as_is_regular(identity)||as_is_directory(identity)||as_is_link(identity)) && identity->size>=0;
}
static int node_open(int parent,const char *name,const ASIdentity *expected) {
 ASIdentity before,after;struct stat parent_stat;
 if(!simple_node(name)||!eligible(expected)||fstat(parent,&parent_stat)||!S_ISDIR(parent_stat.st_mode)||
 parent_stat.st_uid!=getuid()||parent_stat.st_dev!=expected->device){errno=EPERM;return -1;}
 if(as_identity_at(parent,name,&before)||!identities_equal(&before,expected)){errno=ESTALE;return -1;}
 int flags=O_RDONLY|O_CLOEXEC|O_NONBLOCK;
 if(as_is_link(expected))flags|=O_SYMLINK;else flags|=O_NOFOLLOW;
 if(as_is_directory(expected))flags|=O_DIRECTORY;
 int fd=openat(parent,name,flags);if(fd<0)return -1;
 if(as_identity_fd(fd,&after)||!identities_equal(&after,expected)){
  close(fd);errno=ESTALE;return -1;
 }
 return fd;
}
static void hash_number(CC_SHA256_CTX *hash,uint64_t value) {
 unsigned char bytes[8];for(int i=0;i<8;i++)bytes[i]=(unsigned char)(value>>(i*8));
 CC_SHA256_Update(hash,bytes,sizeof(bytes));
}
static void hash_field(CC_SHA256_CTX *hash,const void *bytes,size_t count) {
 hash_number(hash,count);if(count)CC_SHA256_Update(hash,bytes,(CC_LONG)count);
}
static int compare_names(const void *a,const void *b) { return strcmp(*(char *const *)a,*(char *const *)b); }
static int hash_acl(int fd,CC_SHA256_CTX *hash,size_t *used) {
 errno=0;acl_t acl=acl_get_fd_np(fd,ACL_TYPE_EXTENDED);
 if(!acl){if(errno!=ENOENT)return -1;hash_number(hash,0);return 0;}
 ssize_t length=0;char *text=acl_to_text(acl,&length);int saved=errno;acl_free(acl);
 if(!text){errno=saved;return -1;}
 if(length<0||length>NODE_ACL_LIMIT){acl_free(text);errno=E2BIG;return -1;}
 hash_field(hash,text,(size_t)length);*used+=(size_t)length;acl_free(text);return 0;
}
static int hash_attributes(int fd,CC_SHA256_CTX *hash,size_t *used,const NodeBudget *budget,int application_root) {
 char names[NODE_NAMES_LIMIT];char *sorted[1024];
 ssize_t count=flistxattr(fd,NULL,0,0);
 if(count<0)return -1;
 if(count>sizeof(names)){errno=E2BIG;return -1;}
 if(flistxattr(fd,names,(size_t)count,0)!=count){errno=ESTALE;return -1;}
 size_t number=0,offset=0;
 while(offset<(size_t)count){
  size_t length=strnlen(names+offset,(size_t)count-offset);
  if(!length || length==(size_t)count-offset || number==1024){errno=E2BIG;return -1;}
  if(!application_root || strcmp(names+offset,"com.apple.macl"))sorted[number++]=names+offset;
  offset+=length+1;
 }
 qsort(sorted,number,sizeof(char *),compare_names);hash_number(hash,number);*used+=(size_t)count;
 for(size_t i=0;i<number;i++){
  if(!budget_alive(budget))return -1;
  if(i && !strcmp(sorted[i-1],sorted[i])){errno=ESTALE;return -1;}
  ssize_t length=fgetxattr(fd,sorted[i],NULL,0,0,0);
  if(length<0)return -1;
  if(*used>NODE_META_LIMIT || (size_t)length>NODE_META_LIMIT-*used){errno=E2BIG;return -1;}
  void *value=malloc(length?(size_t)length:1);if(!value){errno=ENOMEM;return -1;}
  ssize_t actual=fgetxattr(fd,sorted[i],value,(size_t)length,0,0);
  if(actual!=length){int saved=actual<0?errno:ESTALE;free(value);errno=saved;return -1;}
  hash_field(hash,sorted[i],strlen(sorted[i]));hash_field(hash,value,(size_t)length);
  *used+=(size_t)length;free(value);
 }
 return 0;
}
static int digest_opened_selection(int parent,const char *name,int fd,const ASIdentity *expected,
 const NodeBudget *budget,uint64_t offset,uint64_t length,int application_root,unsigned char output[32]) {
 ASIdentity opened,final,entry;struct stat st;
 if(!budget_alive(budget))return -1;
 if(as_identity_fd(fd,&opened)||!identities_equal(&opened,expected)||fstat(fd,&st)){errno=ESTALE;return -1;}
 if(!eligible(&opened)){errno=EPERM;return -1;}
 if(as_is_regular(&opened) && (uint64_t)opened.size>budget->maximum){errno=EFBIG;return -1;}
 if(as_is_regular(&opened) && (offset>(uint64_t)opened.size || length>(uint64_t)opened.size-offset)){errno=EINVAL;return -1;}
 CC_SHA256_CTX hash;CC_SHA256_Init(&hash);
 // Versioned fields, no struct padding or location/inode/touch time dependence.
 if(application_root)hash_field(&hash,"AppSweepApplicationRoot1",sizeof("AppSweepApplicationRoot1")-1);
 else hash_field(&hash,"AppSweepOwnedNode1",18);
 hash_number(&hash,st.st_mode);hash_number(&hash,st.st_uid);hash_number(&hash,st.st_gid);
 hash_number(&hash,st.st_flags);hash_number(&hash,(uint64_t)st.st_mtimespec.tv_sec);
 hash_number(&hash,(uint64_t)st.st_mtimespec.tv_nsec);
 size_t metadata=0;
 if(hash_acl(fd,&hash,&metadata)||hash_attributes(fd,&hash,&metadata,budget,application_root))return -1;
 if(as_is_regular(&opened)){
  hash_number(&hash,length);char buffer[65536];uint64_t position=0;
  while(position<length){
   if(!budget_alive(budget))return -1;
   size_t wanted=length-position>sizeof(buffer)?sizeof(buffer):(size_t)(length-position);
   ssize_t n=pread(fd,buffer,wanted,(off_t)(offset+position));
   if(n<0 && errno==EINTR)continue;
   if(n<=0){if(!n)errno=ESTALE;return -1;}
   CC_SHA256_Update(&hash,buffer,(CC_LONG)n);position+=n;
  }
 }else if(as_is_link(&opened)){
  char text[NODE_LINK_LIMIT+1];ssize_t count=readlinkat(parent,name,text,sizeof(text));
  if(count<0)return -1;
  if(count>NODE_LINK_LIMIT || (uint64_t)count>budget->maximum){errno=E2BIG;return -1;}
  hash_field(&hash,text,(size_t)count);
 }
 if(!budget_alive(budget))return -1;
 if(as_identity_fd(fd,&final)||!identities_equal(&final,expected)||
    as_identity_at(parent,name,&entry)||!identities_equal(&entry,expected)){errno=ESTALE;return -1;}
 CC_SHA256_Final(output,&hash);return 0;
}
static int digest_opened(int parent,const char *name,int fd,const ASIdentity *expected,
 const NodeBudget *budget,unsigned char output[32]) {
 return digest_opened_selection(parent,name,fd,expected,budget,0,
  expected && as_is_regular(expected)?(uint64_t)expected->size:0,0,output);
}
static int digest_copy_node(int parent,const char *name,int fd,const ASIdentity *expected,
 const NodeBudget *budget,int application_root,unsigned char output[32]) {
 return application_root?digest_opened_selection(parent,name,fd,expected,budget,0,0,1,output):
  digest_opened(parent,name,fd,expected,budget,output);
}
static int configure_budget(uint64_t maximum,int timeout,NodeBudget *budget) {
 if(!getuid()||getuid()!=geteuid()||!maximum||maximum>(1ULL<<40)||timeout<1||timeout>300000){errno=EINVAL;return -1;}
 int64_t now=milliseconds();if(now<0)return -1;
 budget->maximum=maximum;budget->deadline=now+timeout;return 0;
}
static int copy_progress(int what,int stage,copyfile_state_t state,const char *source,const char *dest,void *context) {
 (void)what;(void)stage;(void)state;(void)source;(void)dest;
 return budget_alive(context)?COPYFILE_CONTINUE:COPYFILE_QUIT;
}
#endif

int as_owned_node_digest(int parent,const char *name,const ASIdentity *expected,uint64_t maximum_bytes,int timeout_ms,void *output32) {
#ifdef __APPLE__
 NodeBudget budget;if(!output32||configure_budget(maximum_bytes,timeout_ms,&budget))return -1;
 int fd=node_open(parent,name,expected);if(fd<0)return -1;
 unsigned char digest[32];int result=digest_opened(parent,name,fd,expected,&budget,digest),saved=errno;
 close(fd);if(!result){memcpy(output32,digest,32);saved=0;}errno=saved;return result;
#else
 (void)parent;(void)name;(void)expected;(void)maximum_bytes;(void)timeout_ms;(void)output32;errno=ENOTSUP;return -1;
#endif
}

int as_owned_application_root_digest(int parent,const char *name,const ASIdentity *expected,int timeout_ms,void *output32) {
#ifdef __APPLE__
 NodeBudget budget;
 if(!output32 || !expected || !as_is_directory(expected) || configure_budget(1,timeout_ms,&budget)){errno=EINVAL;return -1;}
 int fd=node_open(parent,name,expected);if(fd<0)return -1;
 unsigned char digest[32];int result=digest_opened_selection(parent,name,fd,expected,&budget,0,0,1,digest),saved=errno;
 close(fd);if(!result){memcpy(output32,digest,32);saved=0;}errno=saved;return result;
#else
 (void)parent;(void)name;(void)expected;(void)timeout_ms;(void)output32;errno=ENOTSUP;return -1;
#endif
}

#ifdef __APPLE__
// Only re-read a newly prepared directory after metadata copying has finished.
// The source's independent digest still has to match. Never repeat fcopyfile,
// change metadata, tolerate another node, or apply this to ordinary node copies.
static int digest_prepared_root(int parent,const char *name,int fd,ASIdentity *expected,
 const NodeBudget *budget,unsigned char output[32]) {
 int64_t now=milliseconds();if(now<0)return -1;
 NodeBudget bounded=*budget;if(bounded.deadline>now+2000)bounded.deadline=now+2000;
 ASIdentity original=*expected,current=*expected;
 for(int attempt=0;attempt<3;attempt++){
  if(!budget_alive(&bounded))return -1;
  if(!digest_copy_node(parent,name,fd,&current,&bounded,1,output)){*expected=current;return 0;}
  if(errno!=ESTALE || attempt==2)return -1;
  ASIdentity fresh,entry,stable;
  if(as_identity_fd(fd,&fresh)||as_identity_at(parent,name,&entry))return -1;
  stable=fresh;stable.changed_seconds=original.changed_seconds;stable.changed_nanoseconds=original.changed_nanoseconds;
  if(!as_is_directory(&fresh)||!identities_equal(&stable,&original)||
     !identities_equal(&fresh,&entry)||identities_equal(&fresh,&current)){errno=ESTALE;return -1;}
  current=fresh;
 }
 errno=ESTALE;return -1;
}
#endif

static int copy_owned_node(int source,const char *name,const ASIdentity *expected,int target,const char *new_name,
 uint64_t maximum_bytes,int timeout_ms,ASIdentity *output_identity,int application_root) {
#ifdef __APPLE__
 NodeBudget budget;ASIdentity parent;
 if(application_root && (!expected || !as_is_directory(expected))){errno=EINVAL;return -1;}
 if(!output_identity||!simple_node(new_name)||configure_budget(maximum_bytes,timeout_ms,&budget))return -1;
 if(!as_private_descriptor(target)||as_identity_fd(target,&parent)||!as_is_directory(&parent)||
 !expected||parent.device!=expected->device){errno=EPERM;return -1;}
 int input=node_open(source,name,expected);if(input<0)return -1;
 int result=-1,saved=0,output=-1;unsigned char before[32],after[32],copied[32];ASIdentity destination;
 if(digest_copy_node(source,name,input,expected,&budget,application_root,before)){saved=errno;goto finish;}
 uint64_t needed=as_is_regular(expected)?(uint64_t)expected->size:0;
 if(as_available_bytes(target)<needed+NODE_META_LIMIT){saved=ENOSPC;goto finish;}
 if(as_is_directory(expected)){
  output=openat(target,new_name,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
  if(output<0){saved=errno;goto finish;}
  if(!as_private_descriptor(output)||as_identity_fd(output,&destination)||destination.device!=expected->device){saved=EPERM;goto finish;}
  if(destination.inode==expected->inode){saved=EINVAL;goto finish;}
  result=-2;
 }else if(as_is_link(expected)){
  char text[NODE_LINK_LIMIT+1];ssize_t n=readlinkat(source,name,text,NODE_LINK_LIMIT+1);
  if(n<0){saved=errno;goto finish;}
  if(n>NODE_LINK_LIMIT){saved=E2BIG;goto finish;}text[n]=0;
  ASIdentity fresh;
  if(as_identity_at(source,name,&fresh)||!identities_equal(&fresh,expected)){saved=ESTALE;goto finish;}
  if(symlinkat(text,target,new_name)){saved=errno;goto finish;}
  result=-2;output=openat(target,new_name,O_RDONLY|O_SYMLINK|O_CLOEXEC);
  if(output<0){saved=errno;goto finish;}
 }else{
  output=openat(target,new_name,O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
  if(output<0){saved=errno;goto finish;}result=-2;
 }
 if(as_identity_fd(output,&destination)||destination.owner!=getuid()||destination.device!=expected->device||
 (destination.mode&S_IFMT)!=(expected->mode&S_IFMT)){saved=ESTALE;goto finish;}
 *output_identity=destination;
 if(!budget_alive(&budget)){saved=errno;goto finish;}
 copyfile_state_t state=copyfile_state_alloc();
 if(!state){saved=ENOMEM;goto finish;}
 int copied_result=copyfile_state_set(state,COPYFILE_STATE_STATUS_CB,(void *)copy_progress);
 if(!copied_result)copied_result=copyfile_state_set(state,COPYFILE_STATE_STATUS_CTX,&budget);
 if(!copied_result)copied_result=fcopyfile(input,output,state,as_is_regular(expected)?COPYFILE_ALL:COPYFILE_METADATA);
 saved=errno;copyfile_state_free(state);if(copied_result)goto finish;
 if(!as_is_link(expected)&&fsync(output)){saved=errno;goto finish;}
 if(fsync(target)){saved=errno;goto finish;}
 if(as_identity_fd(output,&destination)){saved=errno;goto finish;}
 *output_identity=destination;
 if(digest_copy_node(source,name,input,expected,&budget,application_root,after)) {saved=errno;goto finish;}
 int verified=application_root?digest_prepared_root(target,new_name,output,&destination,&budget,copied):
  digest_copy_node(target,new_name,output,&destination,&budget,0,copied);
 if(verified){saved=errno;goto finish;}
 // A source change during destination re-reading must not become acceptable.
 if(application_root && digest_copy_node(source,name,input,expected,&budget,1,after)){saved=errno;goto finish;}
 *output_identity=destination;
 ASIdentity final_parent;
 if(memcmp(before,after,32)||memcmp(before,copied,32)||!as_private_descriptor(target)||
 as_identity_fd(target,&final_parent)||final_parent.device!=parent.device||final_parent.inode!=parent.inode||
 final_parent.mode!=parent.mode||final_parent.owner!=parent.owner){saved=ESTALE;goto finish;}
 result=0;saved=0;
finish:
 if(output>=0)close(output);close(input);errno=saved;return result;
#else
 (void)source;(void)name;(void)expected;(void)target;(void)new_name;(void)maximum_bytes;(void)timeout_ms;(void)output_identity;(void)application_root;errno=ENOTSUP;return -1;
#endif
}
int as_copy_owned_node(int source,const char *name,const ASIdentity *expected,int target,const char *new_name,
 uint64_t maximum_bytes,int timeout_ms,ASIdentity *output_identity) {
 return copy_owned_node(source,name,expected,target,new_name,maximum_bytes,timeout_ms,output_identity,0);
}
int as_copy_owned_application_root(int source,const char *name,const ASIdentity *expected,int target,const char *new_name,
 int timeout_ms,ASIdentity *output_identity) {
 return copy_owned_node(source,name,expected,target,new_name,1,timeout_ms,output_identity,1);
}
int as_copy_owned_regular_range(int source,const char *name,const ASIdentity *expected,int target,const char *new_name,
 uint64_t offset,uint64_t length,uint64_t maximum_bytes,int timeout_ms,ASIdentity *output_identity) {
#ifdef __APPLE__
 NodeBudget budget;ASIdentity parent;
 if(!output_identity||!simple_node(new_name)||configure_budget(maximum_bytes,timeout_ms,&budget))return -1;
 if(!eligible(expected)||!as_is_regular(expected)||expected->links!=1||!length||
 offset>(uint64_t)expected->size||length>(uint64_t)expected->size-offset||
 !as_private_descriptor(target)||as_identity_fd(target,&parent)||!as_is_directory(&parent)||
 parent.device!=expected->device){errno=EPERM;return -1;}
 int input=node_open(source,name,expected);if(input<0)return -1;
 int result=-1,saved=0,output=-1;unsigned char before[32],after[32],copied[32];ASIdentity destination;
 struct stat original;
 if(fstat(input,&original)){saved=errno;goto finish;}
 // Compression metadata describes the whole original data fork. It cannot be
 // attached unchanged to a selected range; do not silently strip or rewrite it.
 if(original.st_flags&UF_COMPRESSED){saved=ENOTSUP;goto finish;}
 errno=0;ssize_t compression=fgetxattr(input,"com.apple.decmpfs",NULL,0,0,0);
 if(compression>=0){saved=ENOTSUP;goto finish;}
 if(errno!=ENOATTR){saved=errno;goto finish;}
 if(digest_opened_selection(source,name,input,expected,&budget,offset,length,0,before)){saved=errno;goto finish;}
 if(as_available_bytes(target)<length+NODE_META_LIMIT){saved=ENOSPC;goto finish;}
 output=openat(target,new_name,O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
 if(output<0){saved=errno;goto finish;}result=-2;
 if(as_identity_fd(output,&destination)||destination.owner!=getuid()||destination.device!=expected->device||
 !as_is_regular(&destination)||destination.links!=1){saved=ESTALE;goto finish;}
 *output_identity=destination;
 unsigned char buffer[65536];uint64_t position=0;
 while(position<length){
  if(!budget_alive(&budget)){saved=errno;goto finish;}
  size_t wanted=length-position>sizeof(buffer)?sizeof(buffer):(size_t)(length-position);
  ssize_t count=pread(input,buffer,wanted,(off_t)(offset+position));
  if(count<0&&errno==EINTR)continue;
  if(count<=0){saved=count?errno:ESTALE;goto finish;}
  size_t written=0;
  while(written<(size_t)count){
   if(!budget_alive(&budget)){saved=errno;goto finish;}
   ssize_t n=pwrite(output,buffer+written,(size_t)count-written,(off_t)(position+written));
   if(n<0&&errno==EINTR)continue;
   if(n<=0){saved=n?errno:EIO;goto finish;}
   written+=(size_t)n;
  }
  position+=(uint64_t)count;
 }
 copyfile_state_t state=copyfile_state_alloc();
 if(!state){saved=ENOMEM;goto finish;}
 int copy_result=copyfile_state_set(state,COPYFILE_STATE_STATUS_CB,(void *)copy_progress);
 if(!copy_result)copy_result=copyfile_state_set(state,COPYFILE_STATE_STATUS_CTX,&budget);
 if(!copy_result)copy_result=fcopyfile(input,output,state,COPYFILE_METADATA);
 saved=errno;copyfile_state_free(state);if(copy_result)goto finish;
 if(!budget_alive(&budget)){saved=errno;goto finish;}
 if(fsync(output)||fsync(target)||as_identity_fd(output,&destination)){saved=errno;goto finish;}
 *output_identity=destination;
 if(destination.size<0||(uint64_t)destination.size!=length||destination.links!=1){saved=ESTALE;goto finish;}
 if(digest_opened_selection(source,name,input,expected,&budget,offset,length,0,after)||
 digest_opened(target,new_name,output,&destination,&budget,copied)){saved=errno;goto finish;}
 ASIdentity final_parent;
 if(memcmp(before,after,32)||memcmp(before,copied,32)||!as_private_descriptor(target)||
 as_identity_fd(target,&final_parent)||final_parent.device!=parent.device||final_parent.inode!=parent.inode||
 final_parent.mode!=parent.mode||final_parent.owner!=parent.owner){saved=ESTALE;goto finish;}
 result=0;saved=0;
finish:
 if(output>=0)close(output);close(input);errno=saved;return result;
#else
 (void)source;(void)name;(void)expected;(void)target;(void)new_name;(void)offset;(void)length;
 (void)maximum_bytes;(void)timeout_ms;(void)output_identity;errno=ENOTSUP;return -1;
#endif
}
#ifdef __APPLE__
#pragma clang diagnostic pop
#endif
