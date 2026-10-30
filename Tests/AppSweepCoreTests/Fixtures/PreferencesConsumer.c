#include <CoreFoundation/CoreFoundation.h>
#include <stdio.h>
#include <string.h>
// Independent disposable app consumer; only its own unique test domain is writable.
int main(int argc,const char **argv) {
 if(argc==1){puts("owned fixture started normally");return 0;}
 if(argc<3)return 2;
 if(argc==3&&!strcmp(argv[1],"--observe-pref")){
  CFStringRef target=CFStringCreateWithCString(NULL,argv[2],kCFStringEncodingUTF8);
  if(!target||!CFStringHasPrefix(target,CFSTR("org.example.nativefixture."))){if(target)CFRelease(target);return 3;}
  CFPropertyListRef value=CFPreferencesCopyAppValue(CFSTR("acceptance-consumer"),target);CFRelease(target);if(!value)return 6;
  char output[1024];int valid=CFGetTypeID(value)==CFStringGetTypeID()&&CFStringGetCString((CFStringRef)value,output,sizeof(output),kCFStringEncodingUTF8);
  CFRelease(value);if(!valid)return 7;puts(output);return 0;
 }
 CFStringRef domain=CFBundleGetIdentifier(CFBundleGetMainBundle());
 CFStringRef requested=CFStringCreateWithCString(NULL,argv[2],kCFStringEncodingUTF8);
 int permitted=domain&&requested&&CFStringHasPrefix(domain,CFSTR("org.example.nativefixture."))&&CFEqual(domain,requested);
 if(requested)CFRelease(requested);if(!permitted)return 3;
 if(argc==3&&!strcmp(argv[1],"--clear-pref")){
  CFPreferencesSetAppValue(CFSTR("acceptance-consumer"),NULL,domain);
  CFPreferencesSetAppValue(CFSTR("acceptance-date"),NULL,domain);
  return CFPreferencesAppSynchronize(domain)?0:5;
 }
 if(argc==3&&!strcmp(argv[1],"--read-date")){
  CFPropertyListRef value=CFPreferencesCopyAppValue(CFSTR("acceptance-date"),domain);if(!value)return 6;
  if(CFGetTypeID(value)!=CFDateGetTypeID()){CFRelease(value);return 7;}
  printf("%.9f\n",CFDateGetAbsoluteTime((CFDateRef)value));CFRelease(value);return 0;
 }
 if(argc==4&&!strcmp(argv[1],"--set-pref")){
  CFStringRef value=CFStringCreateWithCString(NULL,argv[3],kCFStringEncodingUTF8);if(!value)return 4;
  CFPreferencesSetAppValue(CFSTR("acceptance-consumer"),value,domain);CFRelease(value);
  return CFPreferencesAppSynchronize(domain)?0:5;
 }
 if(argc==3&&!strcmp(argv[1],"--read-pref")){
  CFPropertyListRef value=CFPreferencesCopyAppValue(CFSTR("acceptance-consumer"),domain);if(!value)return 6;
  char output[1024];int valid=CFGetTypeID(value)==CFStringGetTypeID()&&CFStringGetCString((CFStringRef)value,output,sizeof(output),kCFStringEncodingUTF8);
  CFRelease(value);if(!valid)return 7;puts(output);return 0;
 }
 return 2;
}
