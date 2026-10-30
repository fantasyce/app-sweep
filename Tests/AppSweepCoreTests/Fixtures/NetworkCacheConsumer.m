#import <Foundation/Foundation.h>
#include <unistd.h>

// A disposable consumer of the public Foundation cache API, never a product rule.
int main(int argc, const char *argv[]) { @autoreleasepool {
    if (argc != 3) return 2;
    NSString *mode = [NSString stringWithUTF8String:argv[1]];
    NSString *root = [NSString stringWithUTF8String:argv[2]];
    NSString *base = NSProcessInfo.processInfo.environment[@"APP_SWEEP_FIXTURES"];
    if (!base || ![base hasPrefix:[NSHomeDirectory() stringByAppendingString:@"/AppSweepAcceptance"]] || ![root hasPrefix:[base stringByAppendingString:@"/"]]) return 3;
    NSURLCache *cache = [[NSURLCache alloc] initWithMemoryCapacity:0 diskCapacity:64*1024*1024 diskPath:root];
    NSURLRequest *request = [NSURLRequest requestWithURL:[NSURL URLWithString:@"https://cache-fixture.invalid/payload"]];
    if ([mode isEqualToString:@"--generate"]) {
        NSMutableData *data = [NSMutableData dataWithLength:512*1024];
        memset(data.mutableBytes, 0x41, data.length);
        NSHTTPURLResponse *response = [[NSHTTPURLResponse alloc] initWithURL:request.URL statusCode:200 HTTPVersion:@"HTTP/1.1" headerFields:@{@"Cache-Control":@"public, max-age=86400", @"Content-Type":@"application/octet-stream"}];
        [cache storeCachedResponse:[[NSCachedURLResponse alloc] initWithResponse:response data:data] forRequest:request];
        [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:3]];
    } else if ([mode isEqualToString:@"--wait"]) {
        [NSData.data writeToFile:[root stringByAppendingPathComponent:@"wait-ready"] atomically:YES];
        NSDate *deadline=[NSDate dateWithTimeIntervalSinceNow:120];
        while (![NSFileManager.defaultManager fileExistsAtPath:[root stringByAppendingPathComponent:@"release-wait"]] && deadline.timeIntervalSinceNow>0) {
            [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.1]];
        }
    } else if (![mode isEqualToString:@"--read"]) return 4;
    printf("%lu\n", (unsigned long)[cache cachedResponseForRequest:request].data.length);
    return 0;
} }
