#import <Foundation/Foundation.h>
#include <unistd.h>

// Disposable native consumer. Its cache location comes from the actual App
// Sandbox, not a constructed fake home or a product-specific format.
int main(int argc,const char *argv[]) { @autoreleasepool {
    if(argc != 2 || getuid() != 501) return 2;
    NSString *identifier=NSBundle.mainBundle.bundleIdentifier;
    if(![identifier hasPrefix:@"org.example.disposable.cache."]) return 3;
    NSString *expected=[@"/Users/localtest/Library/Containers/" stringByAppendingPathComponent:identifier];
    NSString *home=[expected stringByAppendingPathComponent:@"Data"];
    NSURL *url=[NSFileManager.defaultManager URLsForDirectory:NSCachesDirectory inDomains:NSUserDomainMask].firstObject;
    if(![NSHomeDirectory() isEqualToString:home] || ![url.path isEqualToString:[home stringByAppendingPathComponent:@"Library/Caches"]]) return 4;
    NSString *mode=[NSString stringWithUTF8String:argv[1]];
    NSURLCache *cache=[[NSURLCache alloc] initWithMemoryCapacity:0 diskCapacity:8*1024*1024 diskPath:url.path];
    NSURLRequest *request=[NSURLRequest requestWithURL:[NSURL URLWithString:@"https://sandbox-cache-fixture.invalid/payload"]];
    if([mode isEqualToString:@"--generate"]) {
        NSMutableData *data=[NSMutableData dataWithLength:512*1024];memset(data.mutableBytes,0x41,data.length);
        NSHTTPURLResponse *response=[[NSHTTPURLResponse alloc] initWithURL:request.URL statusCode:200 HTTPVersion:@"HTTP/1.1" headerFields:@{@"Cache-Control":@"public, max-age=86400"}];
        [cache storeCachedResponse:[[NSCachedURLResponse alloc] initWithResponse:response data:data] forRequest:request];
        [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:3]];
    } else if(![mode isEqualToString:@"--read"]) return 5;
    NSDictionary *result=@{@"identifier":identifier,@"home":NSHomeDirectory(),@"cache":url.path,@"bytes":@([cache cachedResponseForRequest:request].data.length)};
    NSData *packet=[NSJSONSerialization dataWithJSONObject:result options:0 error:NULL];
    if(!packet) return 6;
    fwrite(packet.bytes,1,packet.length,stdout);putchar('\n');return 0;
} }
