#include "CFSafety.h"
#include <errno.h>
#include <string.h>
#include <unistd.h>
#ifdef __APPLE__
#include <libproc.h>
#include <sys/proc_info.h>
#include <sys/stat.h>
#include <mach/vm_prot.h>
#include <time.h>

static int same_birth(const ASProcessBirth *a, const ASProcessBirth *b) {
 return a->pid==b->pid && a->real_uid==b->real_uid && a->effective_uid==b->effective_uid &&
  a->started_seconds==b->started_seconds && a->started_microseconds==b->started_microseconds;
}
int as_process_birth(int32_t pid, ASProcessBirth *result) {
 if(!result || pid<=1 || getuid()!=geteuid()){errno=EINVAL;return -1;}
 memset(result,0,sizeof(*result));struct proc_bsdinfo info={0};
 if(proc_pidinfo(pid,PROC_PIDTBSDINFO,0,&info,sizeof(info))!=sizeof(info) ||
    info.pbi_pid!=(uint32_t)pid || info.pbi_uid!=geteuid() || info.pbi_ruid!=getuid() ||
    !info.pbi_start_tvsec || info.pbi_start_tvusec>=1000000){errno=EPERM;return -1;}
 result->pid=pid;result->real_uid=info.pbi_ruid;result->effective_uid=info.pbi_uid;
 result->started_seconds=info.pbi_start_tvsec;result->started_microseconds=info.pbi_start_tvusec;return 0;
}
int as_system_resource_reader_image(int32_t pid, const ASProcessBirth *birth) {
 ASProcessBirth before,after;
 if(!birth || as_process_birth(pid,&before) || !same_birth(birth,&before)){errno=ESTALE;return -1;}
 char path[PROC_PIDPATHINFO_MAXSIZE]={0};int count=proc_pidpath(pid,path,sizeof(path));
 if(count<=0 || count>=sizeof(path) || strlen(path)!=(size_t)count ||
    as_process_birth(pid,&after) || !same_birth(birth,&after)){errno=ESTALE;return -1;}
 if(!strcmp(path,"/usr/sbin/usernoted"))return 1;
 if(!strcmp(path,"/System/Library/CoreServices/NotificationCenter.app/Contents/MacOS/NotificationCenter"))return 2;
 return 0;
}
int as_private_readonly_resource_mappings(int32_t pid, const ASIdentity *expected, const ASProcessBirth *birth) {
 ASProcessBirth before,after;
 if(!expected || !birth || birth->pid!=pid || (expected->mode&S_IFMT)!=S_IFREG ||
    expected->links!=1 || expected->size<=0 || expected->size>2*1024*1024 ||
    expected->device!=(uint64_t)(uint32_t)expected->device ||
    as_process_birth(pid,&before) || !same_birth(birth,&before)){errno=ESTALE;return -1;}
 struct timespec started,now;if(clock_gettime(CLOCK_MONOTONIC,&started))return -1;
 uint64_t cursor=0;int found=0;
 for(unsigned steps=0;steps<16384;steps++) {
  if(clock_gettime(CLOCK_MONOTONIC,&now) ||
     (now.tv_sec-started.tv_sec)*1000+(now.tv_nsec-started.tv_nsec)/1000000>2000){errno=ETIMEDOUT;return -1;}
  struct proc_regionwithpathinfo region={0};errno=0;
  int bytes=proc_pidinfo(pid,PROC_PIDREGIONPATHINFO,cursor,&region,sizeof(region));
  if(bytes!=sizeof(region)) {
   if(bytes!=0 || errno!=EINVAL || !steps || as_process_birth(pid,&after) || !same_birth(birth,&after))return -1;
   return found?1:0;
  }
  const struct vinfo_stat *s=&region.prp_vip.vip_vi.vi_stat;
  if(s->vst_dev==(uint32_t)expected->device && s->vst_ino==expected->inode) {
   if(s->vst_mode!=expected->mode || s->vst_uid!=expected->owner || s->vst_nlink!=expected->links ||
      s->vst_size!=expected->size || s->vst_mtime!=expected->modified_seconds ||
      s->vst_mtimensec!=expected->modified_nanoseconds || s->vst_ctime!=expected->changed_seconds ||
      s->vst_ctimensec!=expected->changed_nanoseconds || s->vst_flags){errno=ESTALE;return -1;}
   const struct proc_regioninfo *r=&region.prp_prinfo;
   if(r->pri_protection!=VM_PROT_READ || !(r->pri_max_protection&VM_PROT_READ) ||
      (r->pri_max_protection&~(VM_PROT_READ|VM_PROT_WRITE)) ||
      (r->pri_share_mode!=SM_COW && r->pri_share_mode!=SM_PRIVATE))return 0;
   found=1;
  }
  uint64_t next=region.prp_prinfo.pri_address+region.prp_prinfo.pri_size;
  if(!region.prp_prinfo.pri_size || next<=cursor || next<region.prp_prinfo.pri_address){errno=ESTALE;return -1;}
  cursor=next;
 }
 errno=ETIMEDOUT;return -1;
}
#else
int as_process_birth(int32_t pid, ASProcessBirth *result){(void)pid;(void)result;errno=ENOTSUP;return -1;}
int as_system_resource_reader_image(int32_t pid,const ASProcessBirth *birth){(void)pid;(void)birth;errno=ENOTSUP;return -1;}
int as_private_readonly_resource_mappings(int32_t pid,const ASIdentity *expected,const ASProcessBirth *birth){(void)pid;(void)expected;(void)birth;errno=ENOTSUP;return -1;}
#endif
