#import <Foundation/Foundation.h>
#include <unistd.h>

// Only asks Apple's app-specific script-directory API and reads disposable text.
// It never compiles, executes, or sends Apple events from a user script.
int main(int argc,const char *argv[]) { @autoreleasepool {
    if(argc != 2 || getuid() != 501) return 2;
    NSString *identifier=NSBundle.mainBundle.bundleIdentifier;
    if(![identifier hasPrefix:@"org.example.disposable.scripts."]) return 3;
    NSURL *scripts=[NSFileManager.defaultManager URLsForDirectory:NSApplicationScriptsDirectory inDomains:NSUserDomainMask].firstObject;
    NSString *canonical=[@"/Users/localtest/Library/Application Scripts/" stringByAppendingPathComponent:identifier];
    if(!scripts || ![scripts.URLByResolvingSymlinksInPath.path isEqualToString:canonical]) return 4;
    NSString *mode=[NSString stringWithUTF8String:argv[1]];NSUInteger count=0;
    if([mode isEqualToString:@"--read"]) {
        NSData *data=[NSData dataWithContentsOfURL:[scripts URLByAppendingPathComponent:@"disposable.applescript"]];
        if(![data isEqualToData:[@"return 42\n" dataUsingEncoding:NSUTF8StringEncoding]]) return 5;count=data.length;
    }else if(![mode isEqualToString:@"--locate"]) return 6;
    NSData *packet=[NSJSONSerialization dataWithJSONObject:@{@"identifier":identifier,@"scripts":scripts.path,@"canonical":canonical,@"bytes":@(count)} options:0 error:NULL];
    if(!packet) return 7;fwrite(packet.bytes,1,packet.length,stdout);putchar('\n');return 0;
} }
