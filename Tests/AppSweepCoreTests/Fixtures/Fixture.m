#import <Cocoa/Cocoa.h>
#include <unistd.h>
// Independently written disposable test app. It can only generate data below a task fixture UUID.
int main(int argc, const char **argv) {
 @autoreleasepool {
  if(argc<3)return 2;
  NSString *mode=[NSString stringWithUTF8String:argv[1]];
  NSString *root=[NSString stringWithUTF8String:argv[2]];
  NSString *home=NSHomeDirectory();
  BOOL scoped=[root hasPrefix:[home stringByAppendingString:@"/AppSweepAcceptance/fixtures/"]]||[root hasPrefix:[home stringByAppendingString:@"/AppSweepAcceptance-20261014/fixtures/"]];
  NSString *base=NSProcessInfo.processInfo.environment[@"APP_SWEEP_FIXTURES"];
  scoped=scoped||(base&&[base hasPrefix:[home stringByAppendingString:@"/AppSweepAcceptance"]]&&[root.stringByDeletingLastPathComponent isEqualToString:base]);
  if(!scoped||![[NSUUID alloc] initWithUUIDString:root.lastPathComponent])return 3;
  NSFileManager *fm=[NSFileManager defaultManager];
  NSString *cache=[root stringByAppendingPathComponent:@"Library/Caches/org.example.sweepfixture"];
  NSString *prefs=[root stringByAppendingPathComponent:@"Library/Preferences"];
  if(![fm createDirectoryAtPath:cache withIntermediateDirectories:YES attributes:nil error:nil])return 4;
  if(![fm createDirectoryAtPath:prefs withIntermediateDirectories:YES attributes:nil error:nil])return 4;
  if(![[@"HTTP fixture content" dataUsingEncoding:NSUTF8StringEncoding] writeToFile:[cache stringByAppendingPathComponent:@"payload"] atomically:YES])return 5;
  if(![@{@"fixture":@YES} writeToFile:[prefs stringByAppendingPathComponent:@"org.example.sweepfixture.plist"] atomically:YES])return 5;
  if([mode isEqualToString:@"--wait"]){
   [NSApplication sharedApplication];[NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];
   NSWindow *window=[[NSWindow alloc] initWithContentRect:NSMakeRect(0,0,360,160) styleMask:NSWindowStyleMaskTitled backing:NSBackingStoreBuffered defer:NO];
   window.title=@"Disposable App Sweep fixture";[window center];[window makeKeyAndOrderFront:nil];
   [NSData.data writeToFile:[root stringByAppendingPathComponent:@"wait-ready"] atomically:YES];
   NSDate *deadline=[NSDate dateWithTimeIntervalSinceNow:120];
   [NSTimer scheduledTimerWithTimeInterval:0.1 repeats:YES block:^(NSTimer *timer){
    if([fm fileExistsAtPath:[root stringByAppendingPathComponent:@"release-wait"]]||deadline.timeIntervalSinceNow<=0)[NSApp terminate:nil];
   }];
   [NSApp run];
  }
  return 0;
 }
}
