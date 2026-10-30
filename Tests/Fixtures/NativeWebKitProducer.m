#import <Cocoa/Cocoa.h>
#import <WebKit/WebKit.h>
@interface Delegate : NSObject <NSApplicationDelegate,WKNavigationDelegate>
@property WKWebView *view;
@end
@implementation Delegate
-(void)applicationDidFinishLaunching:(NSNotification*)note {
 self.view=[[WKWebView alloc] initWithFrame:NSMakeRect(0,0,200,200)];
 self.view.navigationDelegate=self;
 [self.view loadHTMLString:@"<html><body>Owned backend acceptance</body></html>" baseURL:nil];
 dispatch_after(dispatch_time(DISPATCH_TIME_NOW,12*NSEC_PER_SEC),dispatch_get_main_queue(),^{exit(3);});
}
-(void)webView:(WKWebView*)view didFinishNavigation:(WKNavigation*)navigation {
 [view evaluateJavaScript:@"window.fixtureBlob=new Blob([new Uint8Array(2097152)]);window.fixtureURL=URL.createObjectURL(fixtureBlob);fetch(fixtureURL).then(r=>r.arrayBuffer()).then(b=>{window.fixtureSize=b.byteLength;});'created';" completionHandler:^(id result,NSError *error){
  if(error){fprintf(stderr,"WebKit script failed\n");exit(4);}
  dispatch_after(dispatch_time(DISPATCH_TIME_NOW,3*NSEC_PER_SEC),dispatch_get_main_queue(),^{
   [view evaluateJavaScript:@"window.fixtureSize" completionHandler:^(id value,NSError *failure){
    if(failure || [value integerValue]!=2097152){fprintf(stderr,"WebKit blob roundtrip failed\n");exit(5);}
    printf("OWNED_WEBKIT_BLOB_ROUNDTRIP_OK\n");fflush(stdout);[NSApp terminate:nil];
   }];
  });
 }];
}
@end
int main(){@autoreleasepool{[NSApplication sharedApplication];[NSApp setActivationPolicy:NSApplicationActivationPolicyProhibited];Delegate*d=[Delegate new];[NSApp setDelegate:d];[NSApp run];}return 0;}
