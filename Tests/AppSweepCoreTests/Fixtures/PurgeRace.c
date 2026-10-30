#include "CFSafety.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
int main(int argc,char **argv) {
 if(argc!=3)return 2;
 if(strcmp(argv[1],"--child")) {
#ifdef __APPLE__
  setenv("DYLD_INSERT_LIBRARIES",argv[2],1);
#else
  setenv("LD_PRELOAD",argv[2],1);
#endif
  execl(argv[0],argv[0],"--child",argv[1],(char*)0);return 3;
 }
 int parent=as_open_directory(argv[2]);if(parent<0)return 4;
 ASIdentity expected;if(as_identity_at(parent,"target",&expected))return 5;
 char target_path[PATH_MAX];snprintf(target_path,sizeof(target_path),"%s/target",argv[2]);
 int target=as_open_directory(target_path);if(target<0)return 7;
 ASVerifiedEntry known={.relative="known"};if(as_identity_at(target,"known",&known.identity))return 8;as_close(target);
 char late[PATH_MAX];if(snprintf(late,sizeof(late),"%s/target/late",argv[2])>=(int)sizeof(late))return 6;
 setenv("AS_TEST_LATE_FILE",late,1);setenv("AS_TEST_PURGE_ARMED","1",1);
 int result=as_remove_verified(parent,"target",&expected,&known,1);as_close(parent);
 return result==0?1:0; // Removing an unregistered late arrival must be refused.
}
