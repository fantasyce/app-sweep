#import <Foundation/Foundation.h>
#include <unistd.h>

int main(int argc,const char *argv[]) { @autoreleasepool {
    if(getuid()!=501 || argc!=2) return 2;
    NSString *identifier=NSBundle.mainBundle.bundleIdentifier;
    if(![identifier hasPrefix:@"org.example.disposable.groups."]) return 3;
    NSString *group=[@"group." stringByAppendingString:identifier];
    NSURL *url=[NSFileManager.defaultManager containerURLForSecurityApplicationGroupIdentifier:group];
    NSString *expected=[@"/Users/localtest/Library/Group Containers/" stringByAppendingPathComponent:group];
    if(!url || ![url.path isEqualToString:expected]) return 4;
    NSString *mode=[NSString stringWithUTF8String:argv[1]];NSURL *file=[url URLByAppendingPathComponent:@"sample.txt"];
    NSData *original=[@"independent group sample\n" dataUsingEncoding:NSUTF8StringEncoding];
    if([mode isEqualToString:@"--generate"]) {
        if(![original writeToURL:file options:NSDataWritingAtomic error:NULL]) return 5;
    }else if(![mode isEqualToString:@"--read"]) return 6;
    NSData *data=[NSData dataWithContentsOfURL:file];if(![data isEqualToData:original]) return 7;
    NSData *packet=[NSJSONSerialization dataWithJSONObject:@{@"identifier":identifier,@"group":group,@"location":url.path,@"bytes":@(data.length)} options:0 error:NULL];
    if(!packet) return 8;fwrite(packet.bytes,1,packet.length,stdout);putchar('\n');return 0;
} }
