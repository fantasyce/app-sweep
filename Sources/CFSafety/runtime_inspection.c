#include "CFSafety.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#ifdef __APPLE__
#include <libproc.h>
#include <sys/sysctl.h>
#include <sys/proc_info.h>

static int matches(const ASProcessBirth *a, const ASProcessBirth *b) {
 return a->pid==b->pid && a->real_uid==b->real_uid && a->effective_uid==b->effective_uid &&
  a->started_seconds==b->started_seconds && a->started_microseconds==b->started_microseconds;
}
int as_process_arguments(int32_t pid,const ASProcessBirth *birth,char *out,size_t cap,size_t *count,char *cwd,size_t cwd_cap) {
 ASProcessBirth before,after; struct proc_vnodepathinfo paths={0};
 if(!birth||!out||!count||!cwd||cap<2||cap>262144||cwd_cap<2||
    as_process_birth(pid,&before)||!matches(birth,&before)){errno=ESTALE;return -1;}
 *count=0;out[0]=0;cwd[0]=0;
 int mib[3]={CTL_KERN,KERN_PROCARGS2,pid};const size_t allocation=262144;size_t bytes=allocation;
 char *raw=calloc(1,allocation);if(!raw)return -1;int result=-1,overrides=0,download_hint=0;
 if(sysctl(mib,3,raw,&bytes,NULL,0)||bytes>allocation||bytes<sizeof(int)+2)goto done;
 int argc=0;memcpy(&argc,raw,sizeof(argc));if(argc<1||argc>4096)goto done;
 size_t p=sizeof(int),n=0;
 while(p<bytes&&raw[p])p++; /* kernel executable path */
 while(p<bytes&&!raw[p])p++;
 for(int i=0;i<argc;i++) {
  size_t start=p;while(p<bytes&&raw[p])p++;
  if(p>=bytes||p-start+1>cap-n)goto done;
  memcpy(out+n,raw+start,p-start+1);n+=p-start+1;p++;
 }
 /* Do not export environment. Preloads/search-path overrides invalidate a
  * manifest-only negative finding; expose no values, including on failure. */
 for(size_t e=p;e<bytes&&raw[e];) {
  size_t end=e;while(end<bytes&&raw[end])end++;
  if(end>=bytes)goto done;
  if((end-e>13&&!memcmp(raw+e,"NODE_OPTIONS=",13)) ||
     (end-e>10&&!memcmp(raw+e,"NODE_PATH=",10)))overrides=1;
  /* Report only a boolean association, never environment keys or values.
   * An explicit module path can supply a direct API through a dynamic loader. */
  const char *modules[]={"/@electron/get","/electron-builder","/app-builder-lib","/electron-download","/@electron/packager"};
  for(size_t j=0;j<sizeof(modules)/sizeof(modules[0]);j++) {
   const char *hit=strstr(raw+e,modules[j]);
   if(hit) {char after=hit[strlen(modules[j])];if(!after||after=='/'||after==' '||after=='\"'||after=='\'')download_hint=1;}
  }
  e=end+1;
 }
 if(proc_pidinfo(pid,PROC_PIDVNODEPATHINFO,0,&paths,sizeof(paths))!=sizeof(paths))goto done;
 size_t len=strnlen(paths.pvi_cdir.vip_path,sizeof(paths.pvi_cdir.vip_path));
 if(!len||len>=sizeof(paths.pvi_cdir.vip_path)||len>=cwd_cap||paths.pvi_cdir.vip_path[0]!='/')goto done;
 if(as_process_birth(pid,&after)||!matches(&before,&after))goto done;
 memcpy(cwd,paths.pvi_cdir.vip_path,len+1);*count=n;result=(overrides?2:0)|(download_hint?4:0);
done:
 // The kernel may update the required size on failure; wipe only our allocation.
 memset(raw,0,allocation);free(raw);
 if(result<0){memset(out,0,cap);cwd[0]=0;*count=0;errno=ESTALE;}return result;
}
int as_javascript_runtime(int32_t pid) {
 char path[PROC_PIDPATHINFO_MAXSIZE]={0};
 if(proc_pidpath(pid,path,sizeof(path))<=0)return -1;
 const char *leaf=strrchr(path,'/');leaf=leaf?leaf+1:path;
 return !strcmp(leaf,"node")||!strcmp(leaf,"nodejs")||!strcmp(leaf,"bun")||!strcmp(leaf,"deno");
}
#else
int as_process_arguments(int32_t p,const ASProcessBirth *b,char *o,size_t c,size_t *n,char *w,size_t z) {
 (void)p;(void)b;(void)o;(void)c;(void)n;(void)w;(void)z;errno=ENOTSUP;return -1;
}
int as_javascript_runtime(int32_t p){(void)p;errno=ENOTSUP;return -1;}
#endif
