#define _GNU_SOURCE
#include <dirent.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
static struct dirent *inject(DIR *directory) {
 static int injected=0;
#ifdef __APPLE__
 // dyld excludes this interposing image when binding its direct call-through.
 struct dirent *(*original)(DIR*)=readdir;
#else
 struct dirent *(*original)(DIR*)=dlsym(RTLD_NEXT,"readdir");
#endif
 if(!injected&&getenv("AS_TEST_PURGE_ARMED")) {
  injected=1;const char *path=getenv("AS_TEST_LATE_FILE");
  if(path){int fd=open(path,O_WRONLY|O_CREAT|O_EXCL,0600);if(fd>=0){write(fd,"unregistered",12);close(fd);}}
 }
 return original(directory);
}
#ifdef __APPLE__
__attribute__((used)) static struct {void *replacement;void *original;} mapping[] __attribute__((section("__DATA,__interpose")))={{(void*)inject,(void*)readdir}};
#else
struct dirent *readdir(DIR *directory){return inject(directory);}
#endif
