#include "CFSafety.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <copyfile.h>
#include <sys/xattr.h>
// This test executable alone interposes descriptor reads. No production hook.
#define as_identity_fd probe_real_identity_fd
#include "../../../Sources/CFSafety/filesystem.c"
#undef as_identity_fd
static ino_t destination_inode;
static int changes, copies, source_root=-1;
static const char *fault;
int as_identity_fd(int fd,ASIdentity *output) {
 int result=probe_real_identity_fd(fd,output);
 if(!result && output->inode==destination_inode && (output->mode&07777)==0755 &&
    (!changes || !strcmp(fault,"continuous") || (!strcmp(fault,"source-after") && changes==1))) {
  if(strcmp(fault,"plain")) {
   changes++;
   if(!strcmp(fault,"source-after") && changes==2) {
    if(fsetxattr(source_root,"org.appsweep.changed-source","changed",7,0,0))return -1;
   } else if(!strcmp(fault,"attribute")) {
    if(fsetxattr(fd,"org.appsweep.unexpected","changed",7,0,0))return -1;
   } else if(!strcmp(fault,"mode")) {
    if(fchmod(fd,0750))return -1;
   } else if(fchmod(fd,0755))return -1;
  }
 }
 return result;
}
int fcopyfile(int source,int target,copyfile_state_t state,copyfile_flags_t flags) {
 typedef int(*Copy)(int,int,copyfile_state_t,copyfile_flags_t);
 Copy original=(Copy)dlsym(RTLD_NEXT,"fcopyfile");
 if(!original){errno=ENOSYS;return -1;}copies++;
 return original(source,target,state,flags);
}
int main(int argc,char **argv) {
 if(argc!=3||!getuid())return 2;fault=argv[2];
 int root=as_open_directory(argv[1]);if(root<0||!as_private_descriptor(root))return 3;
 int source=openat(root,"source",O_RDONLY|O_DIRECTORY|O_NOFOLLOW),target=openat(root,"output",O_RDONLY|O_DIRECTORY|O_NOFOLLOW);
 if(source<0||target<0)return 4;
 source_root=openat(source,"application",O_RDONLY|O_DIRECTORY|O_NOFOLLOW);if(source_root<0)return 4;
 int destination=openat(target,"copy",O_RDONLY|O_DIRECTORY|O_NOFOLLOW);struct stat st;
 if(destination<0||fstat(destination,&st))return 5;destination_inode=st.st_ino;
 ASIdentity expected,created,after;
 if(as_identity_at(source,"application",&expected))return 6;
 int result=!strcmp(fault,"generic")?
  as_copy_owned_node(source,"application",&expected,target,"copy",1024,5000,&created):
  as_copy_owned_application_root(source,"application",&expected,target,"copy",5000,&created);
 int error=errno;
 if(as_identity_at(source,"application",&after))return 7;
 int source_changed=memcmp(&expected,&after,sizeof(expected))!=0;
 if(source_changed!=(!strcmp(fault,"source-after")))return 7;
 printf("ROOT_COPY_RESULT=%d ERROR=%d CHANGES=%d COPIES=%d\n",result,error,changes,copies);
 int success=!strcmp(fault,"once")||!strcmp(fault,"plain");
 if(copies!=1||changes>8||result!=(success?0:-2))return 8;
 if(success && (created.inode!=destination_inode || created.owner!=getuid()))return 9;
 puts(success?"ROOT_COPY_VERIFIED_WITH_ONE_METADATA_COPY":"ROOT_COPY_UNSAFE_OR_UNSTABLE_RETAINED");
 close(source_root);close(destination);close(source);close(target);close(root);return 0;
}
