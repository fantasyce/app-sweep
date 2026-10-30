/* Test-only executable: simulate one failed directory sync after a real swap.
 * It is never linked into the product, service, or installer. */
#include "CFSafety.h"
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>

static int fail_fd=-1,did_fail=0,simulate_rename_eio=0,simulate_rename_before=0,did_rename_eio=0;
int fsync(int fd) {
 if(fd==fail_fd && !did_fail){did_fail=1;errno=EIO;return -1;}
 int (*original)(int)=(int (*)(int))dlsym(RTLD_NEXT,"fsync");
 if(!original){errno=ENOSYS;return -1;}
 return original(fd);
}
int renameatx_np(int first,const char *a,int second,const char *b,unsigned int flags) {
 int (*original)(int,const char *,int,const char *,unsigned int)=
  (int (*)(int,const char *,int,const char *,unsigned int))dlsym(RTLD_NEXT,"renameatx_np");
 if(!original){errno=ENOSYS;return -1;}
 if(simulate_rename_before && !did_rename_eio){did_rename_eio=1;errno=EIO;return -1;}
 int result=original(first,a,second,b,flags);
 if(!result && simulate_rename_eio && !did_rename_eio){did_rename_eio=1;errno=EIO;return -1;}
 return result;
}
static int bound(int parent,const char *name,const ASIdentity *expected) {
 ASIdentity actual;
 return !as_identity_at(parent,name,&actual) && actual.device==expected->device && actual.inode==expected->inode;
}
int main(int argc,char **argv) {
 if((argc!=2 && argc!=3) || !getuid() || getuid()!=geteuid() || argv[1][0]!='/' || strlen(argv[1])>PATH_MAX-32)return 2;
 char a_path[PATH_MAX],b_path[PATH_MAX];
 snprintf(a_path,sizeof(a_path),"%s/installed",argv[1]);snprintf(b_path,sizeof(b_path),"%s/prepared",argv[1]);
 int first=as_open_directory(a_path),second=as_open_directory(b_path);
 if(first<0 || second<0)return 3;
 ASIdentity a,b,ap,bp;
 if(as_identity_at(first,"Application.app",&a) || as_identity_at(second,"replacement",&b) ||
    as_identity_fd(first,&ap) || as_identity_fd(second,&bp))return 4;
 if(argc==3){
  if(strcmp(argv[2],"rename-eio") && strcmp(argv[2],"rename-eio-before"))return 2;
  simulate_rename_eio=1;simulate_rename_before=!strcmp(argv[2],"rename-eio-before");
 }
 fail_fd=simulate_rename_eio?-1:first;
 int result=as_exchange_owned_directories(first,"Application.app",&a,&ap,second,"replacement",&b,&bp);
 if(result!=-2 || (simulate_rename_eio?!did_rename_eio:!did_fail) || errno!=EIO){
  int captured=errno;
  fprintf(stderr,"API result=%d errno=%d simulatedrename=%d swapped=%d/%d",result,captured,did_rename_eio,bound(first,"Application.app",&b),bound(second,"replacement",&a));
  return 5;
 }
 if(simulate_rename_before){
  if(!bound(first,"Application.app",&a) || !bound(second,"replacement",&b))return 9;
  close(first);close(second);
  puts("INDETERMINATE_EXCHANGE_RECONCILED_WITHOUT_BLIND_RETRY");return 0;
 }
 // The caller observes both actual positions. A blind retry would undo an
 // already committed change without knowing that it occurred.
 if(!bound(first,"Application.app",&b) || !bound(second,"replacement",&a))return 6;
 fail_fd=-1;
 ASIdentity next_a,next_b,next_ap,next_bp;
 if(as_identity_at(first,"Application.app",&next_a) || as_identity_at(second,"replacement",&next_b) ||
    as_identity_fd(first,&next_ap) || as_identity_fd(second,&next_bp))return 7;
 if(as_exchange_owned_directories(first,"Application.app",&next_a,&next_ap,second,"replacement",&next_b,&next_bp) ||
    !bound(first,"Application.app",&a) || !bound(second,"replacement",&b))return 8;
 close(first);close(second);
 puts("INDETERMINATE_EXCHANGE_RECONCILED_WITHOUT_BLIND_RETRY");
 return 0;
}
