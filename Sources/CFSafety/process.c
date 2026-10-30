#define _GNU_SOURCE
#include "CFSafety.h"
#include <spawn.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#ifdef __APPLE__
#include <crt_externs.h>
#define AS_ENVIRON (*_NSGetEnviron())
#else
extern char **environ;
#define AS_ENVIRON environ
#endif
static int64_t milliseconds(void) { struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return (int64_t)t.tv_sec*1000+t.tv_nsec/1000000; }
static int run_process(const char *executable,char *const arguments[],char *output,size_t capacity,int timeout_ms,size_t *count,int merge_stderr,int *exit_status,int input_fd) {
 *count=0;*exit_status=-1;
 if(!executable||!arguments||timeout_ms<=0||timeout_ms>30000){errno=EINVAL;return -1;}
 if(input_fd!=-1&&(input_fd<3||fcntl(input_fd,F_GETFD)<0)){errno=EINVAL;return -1;}
 int pipes[2];if(pipe(pipes))return -1;
 // LaunchServices and test callers may have closed standard descriptors.
 // Keep pipe descriptors distinct from stdin/stdout/stderr before child actions.
 for(int index=0;index<2;index++) {
  if(pipes[index]<3) { int duplicate=fcntl(pipes[index],F_DUPFD_CLOEXEC,3);if(duplicate<0){close(pipes[0]);close(pipes[1]);return -1;}close(pipes[index]);pipes[index]=duplicate; }
 }
 fcntl(pipes[0],F_SETFD,FD_CLOEXEC);fcntl(pipes[1],F_SETFD,FD_CLOEXEC);
 posix_spawn_file_actions_t actions;posix_spawn_file_actions_init(&actions);
 if(input_fd!=-1) {
  int error=posix_spawn_file_actions_adddup2(&actions,input_fd,STDIN_FILENO);
  if(!error)error=posix_spawn_file_actions_addclose(&actions,input_fd);
  if(error){posix_spawn_file_actions_destroy(&actions);close(pipes[0]);close(pipes[1]);errno=error;return -1;}
 }
 posix_spawn_file_actions_adddup2(&actions,pipes[1],STDOUT_FILENO);
 posix_spawn_file_actions_addclose(&actions,pipes[0]);
 if(merge_stderr)posix_spawn_file_actions_adddup2(&actions,pipes[1],STDERR_FILENO);
 else posix_spawn_file_actions_addopen(&actions,STDERR_FILENO,"/dev/null",O_WRONLY,0600);
 posix_spawn_file_actions_addclose(&actions,pipes[1]);
 posix_spawnattr_t attrs;posix_spawnattr_init(&attrs);
 posix_spawnattr_setflags(&attrs,POSIX_SPAWN_SETPGROUP);posix_spawnattr_setpgroup(&attrs,0);
 pid_t pid;int error=posix_spawn(&pid,executable,&actions,&attrs,arguments,AS_ENVIRON);
 posix_spawnattr_destroy(&attrs);posix_spawn_file_actions_destroy(&actions);close(pipes[1]);
 if(error){close(pipes[0]);errno=error;return -1;}
 fcntl(pipes[0],F_SETFL,O_NONBLOCK);
 int ended=0,eof=0,status=0,result=0;size_t total=0;int64_t deadline=milliseconds()+timeout_ms;
 while(!ended||!eof) {
  char buffer[8192];ssize_t n=read(pipes[0],buffer,sizeof(buffer));
  if(n>0){if((size_t)n>capacity-total){result=-3;break;}memcpy(output+total,buffer,(size_t)n);total+=(size_t)n;}
  else if(n==0)eof=1;
  else if(errno!=EAGAIN&&errno!=EWOULDBLOCK&&errno!=EINTR){result=-1;break;}
  if(!ended){pid_t waited=waitpid(pid,&status,WNOHANG);if(waited==pid)ended=1;else if(waited<0&&errno!=EINTR){result=-1;break;}}
  if(ended&&eof)break;
  if(milliseconds()>=deadline){result=-2;break;}
  struct pollfd poller={.fd=pipes[0],.events=POLLIN};poll(&poller,1,10);
 }
 close(pipes[0]);
 // This PGID was atomically created by posix_spawn. No unrelated app is signalled.
 if(result){kill(-pid,SIGKILL);if(!ended){int64_t until=milliseconds()+1000;while(milliseconds()<until){pid_t waited=waitpid(pid,&status,WNOHANG);if(waited==pid||waited<0)break;struct timespec pause={0,1000000};nanosleep(&pause,NULL);}}return result;}
 if(!WIFEXITED(status))return -4;
 *exit_status=WEXITSTATUS(status);*count=total;return 0;
}
int as_run_process(const char *executable,char *const arguments[],char *output,size_t capacity,int timeout_ms,size_t *count,int merge_stderr,int *exit_status) {
 return run_process(executable,arguments,output,capacity,timeout_ms,count,merge_stderr,exit_status,-1);
}
int as_run_process_with_input(const char *executable,char *const arguments[],char *output,size_t capacity,int timeout_ms,size_t *count,int merge_stderr,int *exit_status,int input_fd) {
 if(input_fd<3){errno=EINVAL;return -1;}
 return run_process(executable,arguments,output,capacity,timeout_ms,count,merge_stderr,exit_status,input_fd);
}
