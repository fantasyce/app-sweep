#import <Foundation/Foundation.h>
#include <unistd.h>
#include <string.h>

// Independently generated native App Sandbox data; no personal account or network.
int main(int argc,const char *argv[]) { @autoreleasepool {
    if(argc != 2 || getuid() != 501) return 2;
    NSString *identifier=NSBundle.mainBundle.bundleIdentifier;
    if(![identifier hasPrefix:@"org.example.disposable.container."]) return 3;
    NSString *root=[@"/Users/localtest/Library/Containers/" stringByAppendingPathComponent:identifier];
    if(![NSHomeDirectory() isEqualToString:[root stringByAppendingPathComponent:@"Data"]]) return 4;
    NSURL *documents=[NSFileManager.defaultManager URLsForDirectory:NSDocumentDirectory inDomains:NSUserDomainMask].firstObject;
    if(![documents.path isEqualToString:[NSHomeDirectory() stringByAppendingPathComponent:@"Documents"]]) return 5;
    NSURL *file=[documents URLByAppendingPathComponent:@"native-data.bin"];
    NSString *mode=[NSString stringWithUTF8String:argv[1]];
    if([mode isEqualToString:@"--generate"]) {
        if(![NSFileManager.defaultManager createDirectoryAtURL:documents withIntermediateDirectories:YES attributes:nil error:NULL]) return 6;
        NSMutableData *data=[NSMutableData dataWithLength:16*1024];memset(data.mutableBytes,0x5a,data.length);
        if(![data writeToURL:file options:NSDataWritingAtomic error:NULL]) return 7;
    }else if(![mode isEqualToString:@"--read"]) return 8;
    NSData *data=[NSData dataWithContentsOfURL:file];
    if(data.length != 16*1024) return 9;
    const unsigned char *bytes=data.bytes;for(NSUInteger i=0;i<data.length;i++) if(bytes[i] != 0x5a) return 10;
    NSData *packet=[NSJSONSerialization dataWithJSONObject:@{@"identifier":identifier,@"home":NSHomeDirectory(),@"document":file.path,@"bytes":@(data.length)} options:0 error:NULL];
    if(!packet) return 11;fwrite(packet.bytes,1,packet.length,stdout);putchar('\n');return 0;
} }
