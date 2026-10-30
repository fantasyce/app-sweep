#import <Foundation/Foundation.h>
#include <unistd.h>

// Independent disposable consumer of the OS-provided Darwin user cache root.
int main(int argc,const char *argv[]) { @autoreleasepool {
    if(argc != 2 || getuid() != 501) return 2;
    NSString *identifier=NSBundle.mainBundle.bundleIdentifier;
    if(![identifier hasPrefix:@"org.example.disposable.darwin."]) return 3;
    char bytes[4096];size_t length=confstr(_CS_DARWIN_USER_CACHE_DIR,bytes,sizeof(bytes));
    if(!length || length>sizeof(bytes)) return 4;
    NSString *base=[[NSString stringWithUTF8String:bytes] stringByStandardizingPath];
    if([base hasPrefix:@"/var/folders/"]) base=[@"/private" stringByAppendingString:base];
    if(![base hasPrefix:@"/private/var/folders/"] || ![base hasSuffix:@"/C"]) return 5;
    NSString *root=[base stringByAppendingPathComponent:identifier],*mode=[NSString stringWithUTF8String:argv[1]];
    if([mode isEqualToString:@"--generate"]) {
        NSError *error=nil;
        if(![NSFileManager.defaultManager createDirectoryAtPath:root withIntermediateDirectories:NO attributes:@{NSFilePosixPermissions:@0700} error:&error] && error.code != NSFileWriteFileExistsError) return 6;
    }
    NSURLCache *cache=[[NSURLCache alloc] initWithMemoryCapacity:0 diskCapacity:8*1024*1024 diskPath:root];
    NSURLRequest *request=[NSURLRequest requestWithURL:[NSURL URLWithString:@"https://darwin-cache-fixture.invalid/payload"]];
    if([mode isEqualToString:@"--generate"]) {
        NSMutableData *body=[NSMutableData dataWithLength:512*1024];memset(body.mutableBytes,0x41,body.length);
        NSHTTPURLResponse *response=[[NSHTTPURLResponse alloc] initWithURL:request.URL statusCode:200 HTTPVersion:@"HTTP/1.1" headerFields:@{@"Cache-Control":@"public, max-age=86400"}];
        [cache storeCachedResponse:[[NSCachedURLResponse alloc] initWithResponse:response data:body] forRequest:request];
        [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:3]];
    }else if(![mode isEqualToString:@"--read"])return 7;
    NSData *body=[cache cachedResponseForRequest:request].data;
    if(body.length != 512*1024)return 8;
    const unsigned char *payload=body.bytes;for(NSUInteger i=0;i<body.length;i++)if(payload[i]!=0x41)return 9;
    NSData *packet=[NSJSONSerialization dataWithJSONObject:@{@"identifier":identifier,@"root":root,@"bytes":@(body.length)} options:0 error:NULL];
    if(!packet)return 10;fwrite(packet.bytes,1,packet.length,stdout);putchar('\n');return 0;
} }
