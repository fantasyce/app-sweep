#include "CFSafety.h"
#include <copyfile.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
// This executable alone replaces copyfile. Production contains no fault hook.
int fcopyfile(int source,int target,copyfile_state_t state,copyfile_flags_t flags) {
 (void)source;(void)state;(void)flags;
 if(pwrite(target,"partial",7,0)!=7)return -1;
 errno=EIO;return -1;
}
int main(int argc,char **argv) {
 if(argc!=2||!getuid())return 2;
 int root=as_open_directory(argv[1]);if(root<0||!as_private_descriptor(root))return 3;
 int source=openat(root,"source",O_RDONLY|O_DIRECTORY|O_NOFOLLOW),target=openat(root,"output",O_RDONLY|O_DIRECTORY|O_NOFOLLOW);
 ASIdentity expected,created,entry;if(source<0||target<0||as_identity_at(source,"input",&expected))return 4;
 int result=as_copy_owned_node(source,"input",&expected,target,"partial",1024,5000,&created),error=errno;
 if(result!=-2||error!=EIO||as_identity_at(target,"partial",&entry)||entry.inode!=created.inode||entry.device!=created.device)return 5;
 int fd=openat(target,"partial",O_RDONLY|O_NOFOLLOW);char value[8]={0};if(fd<0||read(fd,value,8)!=7||strcmp(value,"partial"))return 6;
 ASIdentity after;if(as_identity_at(source,"input",&after)||after.inode!=expected.inode||after.size!=expected.size||after.changed_seconds!=expected.changed_seconds||after.changed_nanoseconds!=expected.changed_nanoseconds)return 7;
 result=as_copy_owned_regular_range(source,"input",&expected,target,"range-partial",2,7,1024,5000,&created);error=errno;
 if(result!=-2||error!=EIO||as_identity_at(target,"range-partial",&entry)||entry.inode!=created.inode||entry.device!=created.device)return 8;
 int range=openat(target,"range-partial",O_RDONLY|O_NOFOLLOW);char selected[8]={0};
 if(range<0||read(range,selected,8)!=7||strcmp(selected,"partial"))return 9;
 result=as_copy_owned_regular_range(source,"input",&expected,target,"range-partial",2,7,1024,5000,&created);
 if(result!=-1||errno!=EEXIST||as_identity_at(target,"range-partial",&created)||entry.inode!=created.inode||entry.size!=created.size)return 10;
 if(as_identity_at(source,"input",&after)||after.inode!=expected.inode||after.size!=expected.size||after.changed_seconds!=expected.changed_seconds||after.changed_nanoseconds!=expected.changed_nanoseconds)return 11;
 puts("PARTIAL_RANGE_RETAINED_AND_EXISTING_OUTPUT_REFUSES_RETRY");close(range);
 puts("PARTIAL_COPY_RETAINED_WITHOUT_OVERWRITE_OR_BLIND_RETRY");close(fd);close(source);close(target);close(root);return 0;
}
