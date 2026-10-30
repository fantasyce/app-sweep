// Test-only process interruption/failure shim. Never linked into the product.
#include <sys/stat.h>
#include <sys/attr.h>
#include <copyfile.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
static int exchanges,ancestor_syncs,root_reads;
static int mode(const char *wanted) {
 const char *value=getenv("APP_SWEEP_OPTIMIZATION_PROBE_PHASE");return value&&!strcmp(value,wanted);
}
static int path_matches(int fd,const char *suffix,int prefix) {
 const char *root=getenv("APP_SWEEP_OPTIMIZATION_PROBE_HOME");char path[4096],expected[4096];
 if(!root||!*root||fcntl(fd,F_GETPATH,path))return 0;
 if(snprintf(expected,sizeof(expected),"%s%s",root,suffix)>=(int)sizeof(expected))return 0;
 return prefix?!strncmp(path,expected,strlen(expected)):!strcmp(path,expected);
}
static void stop(int code) { fflush(NULL);_exit(code); }
static int test_copy(int in,int out,copyfile_state_t state,copyfile_flags_t flags) {
 int result=fcopyfile(in,out,state,flags);
 if(!result&&(flags&COPYFILE_DATA)&&mode("preparing")&&path_matches(out,"/Library/Application Support/App Sweep/Optimization.noindex/",1))stop(81);
 return result;
}
static int test_exchange(int a,const char *an,int b,const char *bn,unsigned flags) {
 int target=(flags&RENAME_SWAP)&&an&&!strcmp(an,"Disposable Fixture.app")&&path_matches(a,"/Applications",0);
 int result=renameatx_np(a,an,b,bn,flags);
 if(target&&!result){
  exchanges++;root_reads=0;
  if((mode("published")&&exchanges==1)||(mode("restored")&&exchanges==2))stop(mode("published")?84:86);
  if(mode("swap-eio")&&exchanges==1){errno=EIO;return -1;}
 }
 return result;
}
static int test_stat(int directory,const char *name,struct stat *value,int flags) {
 int result=fstatat(directory,name,value,flags);
 if(!result && (mode("root-settle") || mode("root-never-settles")) && exchanges && name && !strcmp(name,"Disposable Fixture.app") && path_matches(directory,"/Applications",0)){
  root_reads++;
  // The C exchange has already read the new entry once. Change only root
  // ctime between the Swift snapshot's initial and final root observations.
  if(root_reads==3 || (mode("root-never-settles") && root_reads>3)){
   if(fchmodat(directory,name,value->st_mode&07777,0))stop(93);
   fprintf(stderr,"OPTIMIZATION_ROOT_CTIME_CHANGE=%d\n",exchanges);fflush(stderr);
   result=fstatat(directory,name,value,flags);
  }
 }
 return result;
}
static int test_sync(int fd) {
 int result=fsync(fd);
 if(result)return result;
 if(path_matches(fd,"/Library/Application Support",0))ancestor_syncs|=1;
 if(path_matches(fd,"/Library/Application Support/App Sweep",0))ancestor_syncs|=2;
 if(mode("sync-after-swap")&&exchanges==1&&path_matches(fd,"/Applications",0)){errno=EIO;return -1;}
 if(!path_matches(fd,"/Library/Application Support/App Sweep/Optimization.noindex/",1))return result;

 int file=openat(fd,"optimization.json",O_RDONLY|O_NOFOLLOW);if(file<0)return result;
 char bytes[131073];ssize_t n=read(file,bytes,sizeof(bytes)-1);close(file);if(n<=0)return result;
 size_t end=0;for(ssize_t i=0;i<n;i++)if(!isspace((unsigned char)bytes[i]))bytes[end++]=bytes[i];bytes[end]=0;
 if(mode("ancestor-sync"))stop(ancestor_syncs==3?91:90);
 if(mode("descriptor-flags")){
  int seen=0,limit=getdtablesize();if(limit>4096)limit=4096;
  for(int candidate=3;candidate<limit;candidate++)if(path_matches(candidate,"/Library/Application Support/App Sweep/Recovery",0)){
   seen=1;int flags=fcntl(candidate,F_GETFD);if(flags<0||!(flags&FD_CLOEXEC))stop(88);
  }
  if(seen)stop(89);
 }

 if(mode("prepared")&&strstr(bytes,"\"status\":\"prepared\""))stop(82);
 if(strstr(bytes,"\"status\":\"publishing\"")){
  if(mode("publishing"))stop(83);
  if(mode("write-failure")){errno=EIO;return -1;}
 }
 if(mode("undoing")&&strstr(bytes,"\"status\":\"undoing\""))stop(85);
 return result;
}
#define INTERPOSE(replacement,replacee) \
 __attribute__((used)) static struct {const void *a,*b;} binding_##replacee \
 __attribute__((section("__DATA,__interpose")))={(const void *)(unsigned long)&replacement,(const void *)(unsigned long)&replacee};
INTERPOSE(test_copy,fcopyfile)
INTERPOSE(test_exchange,renameatx_np)
INTERPOSE(test_sync,fsync)
INTERPOSE(test_stat,fstatat)
