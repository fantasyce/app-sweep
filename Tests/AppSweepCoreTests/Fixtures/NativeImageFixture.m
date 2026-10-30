#import <Cocoa/Cocoa.h>

// Independently generated local pixels for the disposable media-player workflow.
// This is test data creation, never a cleanup or ownership rule.
int main(int argc, const char **argv) {
  @autoreleasepool {
    if (argc != 2) return 2;
    NSString *path = [NSString stringWithUTF8String:argv[1]];
    NSString *expected = [NSHomeDirectory() stringByAppendingPathComponent:@"AppSweepAcceptanceGeneral-20261016/media-fixture.noindex/fixture.png"];
    if (![path isEqualToString:expected] || [NSFileManager.defaultManager fileExistsAtPath:path]) return 3;
    NSBitmapImageRep *image = [[NSBitmapImageRep alloc] initWithBitmapDataPlanes:nil pixelsWide:64 pixelsHigh:64 bitsPerSample:8 samplesPerPixel:4 hasAlpha:YES isPlanar:NO colorSpaceName:NSDeviceRGBColorSpace bytesPerRow:256 bitsPerPixel:32];
    if (!image) return 4;
    unsigned char *pixels = image.bitmapData;
    for (int y = 0; y < 64; y++) for (int x = 0; x < 64; x++) {
      int i = y * 256 + x * 4;
      pixels[i] = x < 32 ? 208 : 78;
      pixels[i+1] = y < 32 ? 180 : 110;
      pixels[i+2] = (x < 32) == (y < 32) ? 92 : 180;
      pixels[i+3] = 255;
    }
    NSData *data = [image representationUsingType:NSBitmapImageFileTypePNG properties:@{}];
    if (!data || ![data writeToFile:path options:NSDataWritingWithoutOverwriting error:nil]) return 5;
    puts("Task-owned media pixels written.");
    return 0;
  }
}
