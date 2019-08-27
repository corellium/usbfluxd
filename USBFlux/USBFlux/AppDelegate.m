//
//  AppDelegate.m
//  USBFlux
//
//  Created by Nikias Bassen on 30.05.18.
//  Copyright © 2018 Corellium. All rights reserved.
//

#import "AppDelegate.h"
#import "Corellium.h"
#import "PasswordEntry.h"
#import "SimpleTextInput.h"
#import "Preferences.h"
#include <Security/Security.h>

#include <sys/sysctl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <spawn.h>

static AuthorizationRef authorization = nil;

@interface AppDelegate ()
{
    NSTimer *checkTimer;
    char *usbfluxd_path;
    char *terminate_path;
    Corellium *corellium;
    NSTimer *enumTimer;
    int usbfluxd_running;
    int no_mdns;
    BOOL autostart_after_config;
    BOOL onSite;
}
@property (weak) IBOutlet NSMenuItem *preferencesSeparator;
@property (weak) IBOutlet NSMenuItem *preferencesItem;
@property (weak) IBOutlet NSTextField *statusLabel;
@property (weak) IBOutlet NSTextField *detailLabel;
@property (weak) IBOutlet NSTextField *apiLabel;
@property (weak) IBOutlet NSWindow *window;
@property (weak) IBOutlet NSButton *startStopButton;
@property (weak) IBOutlet NSButton *cbAutoStart;
@end

struct usbmuxd_header {
    uint32_t length;    // length of message, including header
    uint32_t version;   // protocol version
    uint32_t message;   // message type
    uint32_t tag;       // responses to this query will echo back this tag
} __attribute__((__packed__));

static int socket_connect_unix(const char *filename)
{
    struct sockaddr_un name;
    int sfd = -1;
    struct stat fst;
#ifdef SO_NOSIGPIPE
    int yes = 1;
#endif

    // check if socket file exists...
    if (stat(filename, &fst) != 0) {
        return -1;
    }
    // ... and if it is a unix domain socket
    if (!S_ISSOCK(fst.st_mode)) {
        return -1;
    }
    // make a new socket
    if ((sfd = socket(PF_LOCAL, SOCK_STREAM, 0)) < 0) {
        return -1;
    }

#ifdef SO_NOSIGPIPE
    if (setsockopt(sfd, SOL_SOCKET, SO_NOSIGPIPE, (void*)&yes, sizeof(int)) == -1) {
        close(sfd);
        return -1;
    }
#endif

    // and connect to 'filename'
    name.sun_family = AF_UNIX;
    strncpy(name.sun_path, filename, sizeof(name.sun_path));
    name.sun_path[sizeof(name.sun_path) - 1] = 0;

    if (connect(sfd, (struct sockaddr *) &name, sizeof(name)) < 0) {
        close(sfd);
        return -1;
    }

    return sfd;
}

static int get_process_list(struct kinfo_proc **procList, size_t *procCount)
{
    int err;
    struct kinfo_proc *result;
    bool done;
    static const int name[] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };
    size_t length = 0;
    
    if (!procList || *procList != NULL || !procCount) {
        return EINVAL;
    }
    
    *procCount = 0;
    
    result = NULL;
    done = false;
    do {
        if (result != NULL) {
            err = EFAULT;
            break;
        }
        
        // Call sysctl with a NULL buffer.
        
        length = 0;
        err = sysctl((int*)name, (sizeof(name) / sizeof(*name)) - 1, NULL, &length, NULL, 0);
        if (err == -1) {
            err = errno;
        }
        
        // Allocate an appropriately sized buffer based on the results
        // from the previous call.
        
        if (err == 0) {
            result = (struct kinfo_proc*)malloc(length);
            if (result == NULL) {
                err = ENOMEM;
            }
        }
        
        // Call sysctl again with the new buffer.  If we get an ENOMEM
        // error, toss away our buffer and start again.
        
        if (err == 0) {
            err = sysctl((int *)name, (sizeof(name) / sizeof(*name)) - 1, result, &length, NULL, 0);
            if (err == -1) {
                err = errno;
            }
            if (err == 0) {
                done = true;
            } else if (err == ENOMEM) {
                free(result);
                result = NULL;
                err = 0;
            }
        }
    } while (err == 0 && ! done);
    
    // Clean up and establish post conditions.
    
    if (err != 0 && result != NULL) {
        free(result);
        result = NULL;
    }
    *procList = result;
    if (err == 0) {
        *procCount = length / sizeof(struct kinfo_proc);
    }
    
    return err;
}

NSDictionary* usbfluxdQuery(const char* req_xml, uint32_t req_len)
{
    id result = nil;
    
    int sfd = socket_connect_unix("/var/run/usbmuxd");
    if (sfd < 0) {
        return nil;
    }
    
    char buf[65536];
    if (req_len == 0) {
        req_len = (uint32_t)strlen(req_xml);
    }
    struct usbmuxd_header muxhdr;
    muxhdr.length = sizeof(struct usbmuxd_header) + req_len;
    muxhdr.version = 1;
    muxhdr.message = 8;
    muxhdr.tag = 0;
    
    if (send(sfd, &muxhdr, sizeof(struct usbmuxd_header), 0) == sizeof(struct usbmuxd_header)) {
        if (send(sfd, req_xml, req_len, 0) == req_len) {
            if (recv(sfd, &muxhdr, sizeof(struct usbmuxd_header), 0) == sizeof(struct usbmuxd_header)) {
                if ((muxhdr.version == 1) && (muxhdr.message == 8) && (muxhdr.tag == 0)) {
                    char *p = &buf[0];
                    uint32_t rr = 0;
                    uint32_t total = muxhdr.length - sizeof(struct usbmuxd_header);
                    if (total > sizeof(buf)) {
                        p = malloc(total);
                    } else {
                        p = &buf[0];
                    }
                    while (rr < total) {
                        ssize_t r = recv(sfd, p + rr, total - rr, 0);
                        if (r < 0) {
                            break;
                        }
                        rr += r;
                    }
                    if (rr == total) {
                        NSDictionary *dict = [NSPropertyListSerialization propertyListWithData:[NSData dataWithBytesNoCopy:p length:total freeWhenDone:NO] options:0 format:nil error:nil];
                        result = dict;
                    } else {
                        NSLog(@"Could not get all data back");
                    }
                    if (total > sizeof(buf)) {
                        free(p);
                    }
                }
            } else {
                NSLog(@"didn't receive as much data as we need");
            }
        }
    }
    close(sfd);
    
    return result;
}

@implementation AppDelegate

- (AuthorizationRef)getAuth:(NSString*)msg
{
    AuthorizationRef authorizationRef = NULL;
    OSStatus status = AuthorizationCreate(NULL, kAuthorizationEmptyEnvironment,
                                          kAuthorizationFlagDefaults, &authorizationRef);
    if (status != errAuthorizationSuccess) {
        NSLog(@"%s: AuthorizationCreate failed: %d", __func__, status);
        return nil;
    }
    
    AuthorizationItem right = {kAuthorizationRightExecute, 0, NULL, 0};
    AuthorizationRights rights = {1, &right};
    const char * iconPath      = [[[NSBundle mainBundle] pathForResource: @"AuthIcon" ofType: @"png"] fileSystemRepresentation];
    char *       prompt        = (char *)[msg UTF8String];
    AuthorizationItem environmentItems[] = {
        {kAuthorizationEnvironmentPrompt, strlen(prompt),   (void*)prompt,   0},
        {kAuthorizationEnvironmentIcon,   strlen(iconPath), (void*)iconPath, 0}
    };
    AuthorizationEnvironment environment = {2, environmentItems};
    AuthorizationFlags flags = kAuthorizationFlagDefaults | kAuthorizationFlagInteractionAllowed | kAuthorizationFlagPreAuthorize | kAuthorizationFlagExtendRights;
    
    status = AuthorizationCopyRights(authorizationRef, &rights, &environment, flags, NULL);
    if (status != errAuthorizationSuccess) {
        NSLog(@"%s: AuthorizationCopyRights failed: %d", __func__, status);
        AuthorizationFree(authorizationRef, kAuthorizationFlagDestroyRights);
        return nil;
    }
    return authorizationRef;
}

-(void)destroyAuth:(AuthorizationRef*)auth
{
    if (!auth || !*auth)
        return;
    AuthorizationFree(*auth, kAuthorizationFlagDestroyRights);
    *auth = nil;
}

-(void)runCommandWithAuth:(AuthorizationRef)auth command:(char*)cmd arguments:(char*[])args
{
    FILE *pipe = NULL;
    OSStatus status = AuthorizationExecuteWithPrivileges(auth, cmd, kAuthorizationFlagDefaults, args, &pipe);
    if (status != errAuthorizationSuccess) {
        NSLog(@"Failed to execute %s: %d", cmd, status);
    } else {
        int stat;
        wait(&stat);
        if (pipe) {
            fclose(pipe);
        }
    }
}

- (void)fixupUSBFluxDaemonPermissions
{
    char *command1 = "/usr/sbin/chown";
    char *args1[] = { "0:0", usbfluxd_path, terminate_path, NULL };
    [self runCommandWithAuth:authorization command:command1 arguments:args1];

    char *command2 = "/bin/chmod";
    char *args2[] = { "4755", usbfluxd_path, terminate_path, NULL };
    [self runCommandWithAuth:authorization command:command2 arguments:args2];
}

- (BOOL)checkUSBFluxDaemonPermissions
{
    struct stat fst;
    bzero(&fst, sizeof(struct stat));
    if (stat(usbfluxd_path, &fst) != 0) {
        return NO;
    }
    if ((fst.st_uid != 0) || ((fst.st_mode & S_ISUID) != S_ISUID) || ((fst.st_mode & S_IXUSR) != S_IXUSR) || ((fst.st_mode & S_IRUSR) != S_IRUSR)) {
        return NO;
    }
    bzero(&fst, sizeof(struct stat));
    if (stat(terminate_path, &fst) != 0) {
        return NO;
    }
    if ((fst.st_uid != 0) || ((fst.st_mode & S_ISUID) != S_ISUID) || ((fst.st_mode & S_IXUSR) != S_IXUSR) || ((fst.st_mode & S_IRUSR) != S_IRUSR)) {
        return NO;
    }
    return YES;
}

-(void)missingPermissionsAlert
{
    NSAlert* alert = [[NSAlert alloc] init];
    [alert setAlertStyle:NSAlertStyleWarning];
    [alert addButtonWithTitle:@"OK"];
    [alert setMessageText:@"Missing Permissions"];
    [alert setInformativeText:@"USBFlux cannot be configured without elevated privileges."];
    [alert runModal];
}

-(void)configFailAlert
{
    NSAlert* alert = [[NSAlert alloc] init];
    [alert setAlertStyle:NSAlertStyleWarning];
    [alert addButtonWithTitle:@"OK"];
    [alert setMessageText:@"Error"];
    [alert setInformativeText:@"Failed to configure USBFlux."];
    [alert runModal];
}

-(void)startUSBFluxDaemon
{
    if (![self checkUSBFluxDaemonPermissions]) {
        if (!authorization) {
            authorization = [self getAuth:@"USBFlux needs elevated permissions to connect remote devices to USB."];
        }
        if (!authorization) {
            [self performSelectorOnMainThread:@selector(missingPermissionsAlert) withObject:nil waitUntilDone:YES];
            return;
        }

        [self fixupUSBFluxDaemonPermissions];

        if (![self checkUSBFluxDaemonPermissions]) {
            [self performSelectorOnMainThread:@selector(configFailAlert) withObject:nil waitUntilDone:YES];
            return;
        }
    }
    
    posix_spawnattr_t spawnattr = NULL;
    posix_spawnattr_init(&spawnattr);
    
    posix_spawn_file_actions_t action;
    posix_spawn_file_actions_init(&action);
    
    pid_t pid = 0;
    char *argv[4] = { usbfluxd_path, "-v", NULL, NULL};
    if (no_mdns) {
        argv[2] = "-m";
    }
    char *env[] = { NULL };
    int status = posix_spawn(&pid, argv[0], &action, &spawnattr, argv, env);
    if (status != 0) {
        NSLog(@"posix_spawn failed: %s", strerror(status));
    } else {
        int status = -1;
        waitpid(pid, &status, 0);
    }
}

-(void)stopUSBFluxDaemon
{
    if (![self checkUSBFluxDaemonPermissions]) {
        if (!authorization) {
            authorization = [self getAuth:@"USBFlux needs elevated permissions to connect remote devices to USB."];
        }
        if (!authorization) {
            [self performSelectorOnMainThread:@selector(missingPermissionsAlert) withObject:nil waitUntilDone:YES];
            return;
        }

        [self fixupUSBFluxDaemonPermissions];
        
        if (![self checkUSBFluxDaemonPermissions]) {
            [self performSelectorOnMainThread:@selector(configFailAlert) withObject:nil waitUntilDone:YES];
            return;
        }
    }
    
    struct kinfo_proc *proc_list = NULL;
    size_t proc_count;

    pid_t pid = 0;

    if (get_process_list(&proc_list, &proc_count) != 0) {
        NSLog(@"ERR failed to get process list");
    } else {
        int i;
        for (i = 0; i < proc_count; i++) {
            if (strcmp(proc_list[i].kp_proc.p_comm, "usbfluxd") == 0) {
                pid = proc_list[i].kp_proc.p_pid;
                break;
            }
        }
        free(proc_list);
    }

    char pid_s[10];
    pid_s[0] = '\0';
    char *argv[3] = { terminate_path, pid_s, NULL };
    if (pid > 0) {
        sprintf(pid_s, "%d", pid);
    } else {
        argv[1] = NULL;
    }
    
    posix_spawnattr_t spawnattr = NULL;
    posix_spawnattr_init(&spawnattr);
    
    posix_spawn_file_actions_t action;
    posix_spawn_file_actions_init(&action);
    
    char *env[] = { NULL };
    pid = 0;
    int status = posix_spawn(&pid, argv[0], &action, &spawnattr, argv, env);
    if (status != 0) {
        NSLog(@"posix_spawn failed: %s", strerror(status));
    } else {
        int status = -1;
        waitpid(pid, &status, 0);
    }
}

- (BOOL)isRunning
{
    struct kinfo_proc *proc_list = NULL;
    size_t proc_count;
    
    if (get_process_list(&proc_list, &proc_count) != 0) {
        NSLog(@"ERR failed to get process list");
        return NO;
    }
    
    int i;
    BOOL found = NO;
    for (i = 0; i < proc_count; i++) {
        if (strcmp((&proc_list[i])->kp_proc.p_comm, "usbfluxd") == 0) {
            found = YES;
            break;
        }
    }
    free(proc_list);

    return found;
}

- (NSDictionary*)getInstances
{
    const char req_xml[] = "<plist version=\"1.0\"><dict><key>MessageType</key><string>Instances</string></dict></plist>";
    NSDictionary *dict = usbfluxdQuery(req_xml, sizeof(req_xml));
    return (dict) ? [dict objectForKey:@"Instances"] : nil;
}

- (void)checkStatus:(NSTimer*)timer
{
    if (![self.window isVisible]) {
        return;
    }
    NSDictionary *instances = [self getInstances];
    if (instances) {
        usbfluxd_running = 1;
        self.statusLabel.stringValue = @"USBFlux is running.";
        self.startStopButton.title = @"Stop";
        self.startStopButton.tag = 1;
        self.startStopButton.enabled = YES;
        [self.window makeFirstResponder:self.startStopButton];
        self.cbAutoStart.focusRingType = NSFocusRingTypeDefault;
        int local_devices = 0;
        int local_count = 0;
        int remote_devices = 0;
        int remote_count = 0;
        for (NSString *key in instances) {
            NSDictionary *entry = [instances objectForKey:key];
            if ([[entry objectForKey:@"IsUnix"] boolValue]) {
                local_devices += [[entry objectForKey:@"DeviceCount"] intValue];
                local_count++;
            } else {
                remote_devices += [[entry objectForKey:@"DeviceCount"] intValue];
                remote_count++;
            }
        }
        NSDictionary* localInst = [instances objectForKey:@"0"];
        if (localInst) {
            local_devices = [[localInst objectForKey:@"DeviceCount"] intValue];
        }
        self.detailLabel.stringValue = [NSString stringWithFormat:@"%d Device%s (%d Local / %d Remote)", local_devices+remote_devices, (local_devices+remote_devices == 1) ? "" : "s", local_devices, remote_devices];
        self.detailLabel.hidden = NO;
    } else {
        usbfluxd_running = 0;
        self.statusLabel.stringValue = @"USBFlux is not running.";
        self.startStopButton.title = @"Start";
        self.startStopButton.tag = 0;
        self.startStopButton.enabled = YES;
        [self.window makeFirstResponder:self.startStopButton];
        self.cbAutoStart.focusRingType = NSFocusRingTypeDefault;
        self.detailLabel.hidden = YES;
    }
}

- (void)applicationWillFinishLaunching:(NSNotification *)notification
{
    const char *executable_path = [[[NSBundle mainBundle] executablePath] fileSystemRepresentation];
    if (executable_path) {
        struct statvfs fs;
        bzero(&fs, sizeof(struct statvfs));
        if (statvfs(executable_path, &fs) == 0) {
            if (fs.f_flag & ST_RDONLY) {
                [self.window setIsVisible:NO];
                NSAlert* alert = [[NSAlert alloc] init];
                [alert setAlertStyle:NSAlertStyleWarning];
                [alert addButtonWithTitle:@"OK"];
                [alert setMessageText:@"Cannot run from read-only volume"];
                [alert setInformativeText:@"Please drag USBFlux.app into your Applications folder in order to run it."];
                [alert runModal];
                kill(getpid(), SIGTERM);
            }
        }
    }
    no_mdns = 0;
    autostart_after_config = NO;
}

- (int)addInstance:(NSString*)host port:(unsigned int)port
{
    char req_xml[256];
    unsigned int req_len = snprintf(req_xml, 255, "<plist version=\"1.0\"><dict><key>MessageType</key><string>AddInstance</string><key>HostAddress</key><string>%s</string><key>PortNumber</key><integer>%u</integer></dict></plist>", [host UTF8String], port);
    NSDictionary *dict = usbfluxdQuery(req_xml, req_len);
    NSNumber *num = (dict) ? [dict objectForKey:@"Number"] : nil;
    if (num) {
        return [num intValue];
    }
    return -1;
}

- (int)removeInstance:(NSString*)host port:(unsigned int)port
{
    char req_xml[256];
    unsigned int req_len = snprintf(req_xml, 255, "<plist version=\"1.0\"><dict><key>MessageType</key><string>RemoveInstance</string><key>HostAddress</key><string>%s</string><key>PortNumber</key><integer>%u</integer></dict></plist>", [host UTF8String], port);
    NSDictionary *dict = usbfluxdQuery(req_xml, req_len);
    NSNumber *num = (dict) ? [dict objectForKey:@"Number"] : nil;
    if (num) {
        return [num intValue];
    }
    return -1;
}

- (void)getRemoteInstances
{
    if (corellium && usbfluxd_running) {
        NSError *err = nil;
        NSArray *instances = [corellium instances:&err withQuery:@"returnAttr=port-adb,port-usbmuxd,serviceIp,state"];
        if (err) {
            [self setApiStatus:[NSString stringWithFormat:@"%@ disconnected", corellium.domain]];
        } else {
            [self setApiStatus:[NSString stringWithFormat:@"Connected to %@", corellium.domain]];
        }
        for (NSDictionary *instance in instances) {
            /* must be on */
            NSString *state = [instance objectForKey:@"state"];
            if (![state isEqualToString:@"on"])
                continue;
            /* not android */
            id portAdb = [instance objectForKey:@"port-adb"];
            if (portAdb)
                continue;
            /* has usbmuxd port */
            NSString *usbmuxdPort = [instance objectForKey:@"port-usbmuxd"];
            if (!usbmuxdPort)
                continue;
            /* and service ip */
            NSString *serviceIp = [instance objectForKey:@"serviceIp"];
            if (!serviceIp)
                continue;
            [self addInstance:serviceIp port:(unsigned int)[usbmuxdPort intValue]];
        }
    }
}

- (void)enumDevices:(NSTimer*)timer
{
    [NSThread detachNewThreadSelector:@selector(getRemoteInstances) toTarget:self withObject:nil];
}

- (void)startEnumTimer
{
    [self enumDevices:nil];
    enumTimer = [NSTimer scheduledTimerWithTimeInterval:10.0 target:self selector:@selector(enumDevices:) userInfo:nil repeats:YES];
}

- (void)setApiStatus:(NSString*)status
{
    [self.apiLabel performSelectorOnMainThread:@selector(setStringValue:) withObject:status waitUntilDone:NO];
}

- (void)timeoutRetryLogin:(NSMutableDictionary*)options
{
    [self performSelector:@selector(doTryLogin:) withObject:options afterDelay:10.0];
}

- (void)tryLogin:(NSMutableDictionary*)options
{
    NSString *domain = [options objectForKey:@"domain"];
    NSString *protocol = [options objectForKey:@"protocol"];
    NSString *fullDomain = [NSString stringWithFormat:@"%@://%@", protocol, domain];
    NSString *totp = [options objectForKey:@"totp"];
    [self setApiStatus:[NSString stringWithFormat:@"Connecting to %@ ...", domain]];
    Corellium *corelliumTest = [[Corellium alloc] initWithDomain:fullDomain username:[options objectForKey:@"username"] password:[options objectForKey:@"password"] totp:totp];
    NSError *err = nil;
    if (![corelliumTest login:&err]) {
        [self setApiStatus:@""];
        if (err.code == NSURLErrorTimedOut && ![[options objectForKey:@"onError"] isEqualToString:@"runConfigureDomain"]) {
            [self setApiStatus:[NSString stringWithFormat:@"Timeout while connecting to %@", domain]];
            [self performSelectorOnMainThread:@selector(timeoutRetryLogin:) withObject:options waitUntilDone:NO];
        } else if ([err.domain isEqualToString:@"CorelliumDomain"] && err.code == 401) {
            dispatch_async(dispatch_get_main_queue(), ^{
                SimpleTextInput *totpEntry = [[SimpleTextInput alloc] init];
                [totpEntry setMessageText:@"Enter One-Time Code"];
                [totpEntry setInformativeText:@"Multi-factor authentication is enabled. Please enter your current one-time code."];
                [totpEntry setPlaceholder:@"000000"];
                if ([totpEntry runModal] == NSAlertFirstButtonReturn) {
                    NSMutableDictionary *newOptions = [[NSMutableDictionary alloc] initWithDictionary:options];
                    [newOptions setObject:[totpEntry textValue] forKey:@"totp"];
                    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                        [self tryLogin:newOptions];
                    });
                }
            });
        } else {
            dispatch_async(dispatch_get_main_queue(), ^{
                NSAlert *alert = [[NSAlert alloc] init];
                [alert setMessageText:[NSString stringWithFormat:@"Login failed at %@", fullDomain]];
                [alert setInformativeText:@"Make sure domain name and credentials are correct"];
                [alert setAlertStyle:NSAlertStyleCritical];
                [alert performSelectorOnMainThread:@selector(runModal) withObject:nil waitUntilDone:YES];
                SEL sel = NSSelectorFromString([options objectForKey:@"onError"]);
                if (sel) {
                    [self performSelectorOnMainThread:sel withObject:options waitUntilDone:NO];
                }
            });
        }
        return;
    } else {
        [self setApiStatus:@""];
        NSString *username = [options objectForKey:@"username"];
        NSString *password = [options objectForKey:@"password"];
        CFStringRef proto = nil;
        if ([protocol isEqualToString:@"https"]) {
            proto = kSecAttrProtocolHTTPS;
        } else if ([protocol isEqualToString:@"http"]) {
            proto = kSecAttrProtocolHTTP;
        } else {
            proto = kSecAttrProtocolHTTPS;
        }
        
        CFTypeRef check_keys[] = { kSecClass, kSecAttrServer, kSecAttrProtocol, kSecMatchLimit, kSecReturnData, kSecReturnAttributes };
        CFTypeRef check_values[] = { kSecClassInternetPassword, (__bridge CFStringRef)domain, proto, kSecMatchLimitOne, kCFBooleanTrue, kCFBooleanTrue };
        CFDictionaryRef query = CFDictionaryCreate(kCFAllocatorDefault, check_keys, check_values, 6, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        CFTypeRef pwData = NULL;
        OSStatus status = SecItemCopyMatching(query, &pwData);
        CFRelease(query);
        if (status == errSecSuccess) {
            /* item already present in keychain, check if we need to update it */
            NSDictionary *creds = (__bridge NSDictionary*)pwData;
            NSString *old_username = [creds objectForKey:(__bridge NSString*)kSecAttrAccount];
            NSData *passwd = [creds objectForKey:(__bridge NSString*)kSecValueData];
            NSString *old_password = (passwd) ? [[NSString alloc] initWithData:passwd encoding:NSUTF8StringEncoding] : nil;
            CFRelease(pwData);
            if (![username isEqualToString:old_username] || ![password isEqualToString:old_password]) {
                /* update with new credentials */
                CFDictionaryRef update_query = CFDictionaryCreate(kCFAllocatorDefault, check_keys, check_values, 4, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
                NSData *d_passwd =[password dataUsingEncoding:NSUTF8StringEncoding];
                CFTypeRef values[] = { (__bridge CFStringRef)username, (__bridge CFDataRef)d_passwd };
                CFTypeRef keys[] = { kSecAttrAccount, kSecValueData };
                CFDictionaryRef update_data = CFDictionaryCreate(kCFAllocatorDefault, keys, values, 2, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
                status = SecItemUpdate(update_query, update_data);
                CFRelease(update_data);
                CFRelease(update_query);
                if (status != errSecSuccess) {
                    dispatch_async(dispatch_get_main_queue(), ^{
                        NSAlert *alert = [[NSAlert alloc] init];
                        [alert setMessageText:[NSString stringWithFormat:@"Failed to update credentials in keychain (error %d)", status]];
                        [alert setAlertStyle:NSAlertStyleCritical];
                        [alert runModal];
                    });
                    return;
                }
            }
            CFPreferencesSetAppValue(CFSTR("Domain"), (__bridge CFStringRef)fullDomain, APPID);
            CFPreferencesAppSynchronize(APPID);
        } else {
            /* not present, create new item in keychain */
            NSData *d_passwd =[password dataUsingEncoding:NSUTF8StringEncoding];
            CFTypeRef values[] = { kSecClassInternetPassword, (__bridge CFStringRef)domain, proto, (__bridge CFStringRef)username, (__bridge CFDataRef)d_passwd };
            CFTypeRef keys[] = { kSecClass, kSecAttrServer, kSecAttrProtocol, kSecAttrAccount, kSecValueData };
            CFDictionaryRef attribs = CFDictionaryCreate(kCFAllocatorDefault, keys, values, 5, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
            status = SecItemAdd(attribs, NULL);
            CFRelease(attribs);
            if (status == errSecSuccess) {
                CFPreferencesSetAppValue(CFSTR("Domain"), (__bridge CFStringRef)fullDomain, APPID);
                CFPreferencesAppSynchronize(APPID);
            } else {
                dispatch_async(dispatch_get_main_queue(), ^{
                    NSAlert *alert = [[NSAlert alloc] init];
                    [alert setMessageText:[NSString stringWithFormat:@"Failed to store credentials in keychain (error %d)", status]];
                    [alert setAlertStyle:NSAlertStyleCritical];
                    [alert runModal];
                });
                return;
            }
        }
        no_mdns = 1;
        corellium = corelliumTest;
        corellium.domain = domain;
        [self setApiStatus:[NSString stringWithFormat:@"Connected to %@", domain]];
        [self performSelectorOnMainThread:@selector(startEnumTimer) withObject:nil waitUntilDone:NO];
        [self performSelectorOnMainThread:@selector(autoStartDaemonIfRequired) withObject:nil waitUntilDone:NO];
    }
}

- (void)parseDomain:(NSString*)inStr domainOut:(NSString**)outDomain schemeOut:(NSString**)outScheme
{
    NSString *domain = [inStr stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    NSRange schemeRange = [domain rangeOfString:@"://"];
    NSString *scheme = nil;
    if (schemeRange.location != NSNotFound) {
        scheme = [domain substringWithRange:NSMakeRange(0, schemeRange.location)];
        domain = [domain substringFromIndex:schemeRange.location + schemeRange.length];
    } else {
        /* default to https */
        scheme = @"https";
    }
    NSRange slashRange = [domain rangeOfString:@"/"];
    if (slashRange.location != NSNotFound) {
        domain = [domain substringToIndex:slashRange.location];
    }
    *outDomain = domain;
    *outScheme = scheme;
}

- (void)runConfigureDomain:(NSMutableDictionary*)options
{
    [self performSelector:@selector(configureDomain) withObject:nil afterDelay:0.3];
}

- (void)configureDomain
{
    SimpleTextInput *domainEntry = [[SimpleTextInput alloc] init];
    [domainEntry setMessageText:@"Enter Corellium domain"];
    [domainEntry setInformativeText:@"https: will be assumed if not specified"];
    [domainEntry setPlaceholder:@"https://hostname.domain.com"];
    if ([domainEntry runModal] == NSAlertFirstButtonReturn) {
        if ([self isRunning]) {
            [NSThread detachNewThreadSelector:@selector(stopUSBFluxDaemon) toTarget:self withObject:nil];
        }
        if ([[domainEntry textValue] isCaseInsensitiveLike:@"none"]) {
            corellium = nil;
            [enumTimer invalidate];
            [self setApiStatus:@""];
            CFPreferencesSetAppValue(CFSTR("Domain"), CFSTR(""), APPID);
            CFPreferencesAppSynchronize(APPID);
            no_mdns = 0;
            return;
        }
        autostart_after_config = YES;
        NSString *scheme = nil;
        NSString *domain = nil;
        [self parseDomain:[domainEntry textValue] domainOut:&domain schemeOut:&scheme];
        if (![scheme isEqualToString:@"https"] && ![scheme isEqualToString:@"http"]) {
            NSAlert *alert = [[NSAlert alloc] init];
            [alert setMessageText:[NSString stringWithFormat:@"Unsupported protocol '%@'", scheme]];
            [alert setInformativeText:@"Make sure domain name is correct."];
            [alert setAlertStyle:NSAlertStyleCritical];
            [alert runModal];
            [self performSelector:@selector(configureDomain) withObject:nil afterDelay:0.3];
            return;
        }

        PasswordEntry *pwprompt = [[PasswordEntry alloc] init];
        [pwprompt setInformativeText:[NSString stringWithFormat:@"Domain: %@://%@", scheme, domain]];
        if ([pwprompt runModal] == NSAlertFirstButtonReturn) {
            if ([self isRunning]) {
                [NSThread detachNewThreadSelector:@selector(stopUSBFluxDaemon) toTarget:self withObject:nil];
            }
            corellium = nil;
            [enumTimer invalidate];
            [self setApiStatus:@""];
            /*if (usbfluxd_running) {
                NSDictionary *instances = [self getInstances];
                for (NSString *key in instances) {
                    NSDictionary *entry = [instances objectForKey:key];
                    if (![[entry objectForKey:@"IsUnix"] boolValue]) {
                        NSString *host = [entry objectForKey:@"Host"];
                        unsigned int port = [[entry objectForKey:@"Port"] intValue];
                        [self removeInstance:host port:port];
                    }
                }
            }*/
            NSMutableDictionary *options = [[NSMutableDictionary alloc] init];
            [options setObject:domain forKey:@"domain"];
            [options setObject:scheme forKey:@"protocol"];
            [options setObject:[pwprompt userValue] forKey:@"username"];
            [options setObject:[pwprompt passValue] forKey:@"password"];
            [options setObject:@"runConfigureDomain:" forKey:@"onError"];
            [NSThread detachNewThreadSelector:@selector(tryLogin:) toTarget:self withObject:options];
        }
    }
}

- (void)runTryLogin:(NSMutableDictionary*)options
{
    [options removeObjectForKey:@"password"];
    [self performSelector:@selector(doTryLogin:) withObject:options afterDelay:0.3];
}

- (void)doTryLogin:(NSMutableDictionary*)options
{
    NSString *domain = [options objectForKey:@"domain"];
    NSString *scheme = [options objectForKey:@"protocol"];
    NSString *username = [options objectForKey:@"username"];
    NSString *password = [options objectForKey:@"password"];
    if (!username || !password) {
        PasswordEntry *pwprompt = [[PasswordEntry alloc] init];
        [pwprompt setInformativeText:[NSString stringWithFormat:@"Domain: %@://%@", scheme, domain]];
        [pwprompt setUserValue:username];
        if ([pwprompt runModal] == NSAlertFirstButtonReturn) {
            username = [pwprompt userValue];
            password = [pwprompt passValue];
        } else {
            username = nil;
            password = nil;
        }
    }
    if (!username || !password) {
        return;
    }
    
    [options setObject:username forKey:@"username"];
    [options setObject:password forKey:@"password"];

    [NSThread detachNewThreadSelector:@selector(tryLogin:) toTarget:self withObject:options];
}

- (IBAction)preferencesClicked:(id)sender
{
    [self configureDomain];
}

- (void)autoStartDaemonIfRequired
{
    CFPreferencesAppSynchronize(APPID);
    Boolean existsAndValid = NO;
    Boolean shouldAutoStart = CFPreferencesGetAppBooleanValue(CFSTR("AutoStart"), APPID, &existsAndValid);
    if (existsAndValid && shouldAutoStart) {
        self.cbAutoStart.state = NSControlStateValueOn;
    }
    if (autostart_after_config || (existsAndValid && shouldAutoStart)) {
        if (![self isRunning]) {
            self.cbAutoStart.focusRingType = NSFocusRingTypeNone;
            self.startStopButton.enabled = NO;
            [NSThread detachNewThreadSelector:@selector(startUSBFluxDaemon) toTarget:self withObject:nil];
        }
    }
}

- (void)startCheckTimer
{
    [self checkStatus:nil];
    checkTimer = [NSTimer scheduledTimerWithTimeInterval:1.0 target:self selector:@selector(checkStatus:) userInfo:nil repeats:YES];
}

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification
{
    [[NSApp mainWindow] setDelegate:self];
    self.cbAutoStart.focusRingType = NSFocusRingTypeNone;

    CFPreferencesAppSynchronize(APPID);
    
    Boolean existsAndValid = NO;
    Boolean shouldAutoStart = CFPreferencesGetAppBooleanValue(CFSTR("AutoStart"), APPID, &existsAndValid);
    if (existsAndValid && shouldAutoStart) {
        self.cbAutoStart.state = NSControlStateValueOn;
    }

    NSString *usbfluxdPath = [[NSBundle mainBundle] pathForResource:@"usbfluxd" ofType:nil];
    if (![[NSFileManager defaultManager] fileExistsAtPath:usbfluxdPath]) {
        usbfluxd_path = NULL;
        NSAlert* alert = [[NSAlert alloc] init];
        [alert setAlertStyle:NSAlertStyleWarning];
        [alert addButtonWithTitle:@"OK"];
        [alert setMessageText:@"Missing File"];
        [alert setInformativeText:@"The required file usbfluxd could not be found in the resources directory."];
        [alert runModal];
    } else {
        usbfluxd_path = strdup([usbfluxdPath fileSystemRepresentation]);
    }
    NSString *terminatePath = [[NSBundle mainBundle] pathForResource:@"terminate" ofType:@"sh"];
    if (![[NSFileManager defaultManager] fileExistsAtPath:terminatePath]) {
        terminate_path = NULL;
        NSAlert* alert = [[NSAlert alloc] init];
        [alert setAlertStyle:NSAlertStyleWarning];
        [alert addButtonWithTitle:@"OK"];
        [alert setMessageText:@"Missing File"];
        [alert setInformativeText:@"The required file terminate.sh could not be found in the resources directory."];
        [alert runModal];
    } else {
        terminate_path = strdup([terminatePath fileSystemRepresentation]);
    }
    if (usbfluxd_path && terminate_path) {
        CFStringRef usbfluxDomain = nil;
        NSString *domainConf = [[NSBundle mainBundle] pathForResource:@"domain" ofType:@"conf"];
        if ([[NSFileManager defaultManager] fileExistsAtPath:domainConf]) {
            onSite = YES;
            NSDictionary *fileAttr = [[NSFileManager defaultManager] attributesOfItemAtPath:domainConf error:nil];
            NSDate *domainConfModTime = [fileAttr objectForKey:NSFileModificationDate];
            CFPreferencesAppSynchronize(APPID);
            CFDateRef domainConfigTime = CFPreferencesCopyAppValue(CFSTR("DomainConfigured"), APPID);
            if (!domainConfigTime || [domainConfModTime timeIntervalSinceDate:(__bridge NSDate*)domainConfigTime] > 0) {
                /* load config from file */
                NSDictionary *domainConfig = nil;
                @try {
                    domainConfig = [[NSDictionary alloc] initWithContentsOfFile:domainConf];
                } @catch (NSException *e) { }
                if (domainConfig) {
                    Boolean autoStart = [[domainConfig objectForKey:@"AutoStart"] boolValue];
                    if (autoStart) {
                        CFPreferencesSetAppValue(CFSTR("AutoStart"), (autoStart) ? kCFBooleanTrue :  kCFBooleanFalse, APPID);
                    }
                    NSString *domain = [domainConfig objectForKey:@"Domain"];
                    if (domain) {
                        CFPreferencesSetAppValue(CFSTR("Domain"), (__bridge CFStringRef)domain, APPID);
                    }
                }
                usbfluxDomain = CFPreferencesCopyAppValue(CFSTR("Domain"), APPID);
                if (!usbfluxDomain || CFEqual((usbfluxDomain), CFSTR(""))) {
                    CFPreferencesSetAppValue(CFSTR("Domain"), nil, APPID);
                    if (usbfluxDomain) {
                        CFRelease(usbfluxDomain);
                        usbfluxDomain = nil;
                    }
                }
                CFPreferencesSetAppValue(CFSTR("DomainConfigured"), (__bridge CFDateRef)[NSDate date], APPID);
                CFPreferencesAppSynchronize(APPID);
            }
            if (domainConfigTime) {
                CFRelease(domainConfigTime);
            }
        } else {
            onSite = NO;
            usbfluxDomain = CFStringCreateCopy(NULL, CFSTR(""));
            CFPreferencesSetAppValue(CFSTR("Domain"), CFSTR(""), APPID);
            CFPreferencesAppSynchronize(APPID);
        }
        
        if (!onSite) {
            self.preferencesSeparator.hidden = YES;
            self.preferencesItem.hidden = YES;
        }
        
        if (!usbfluxDomain) {
            usbfluxDomain = CFPreferencesCopyAppValue(CFSTR("Domain"), APPID);
        }
        if (!usbfluxDomain) {
            NSAlert *alert = [[NSAlert alloc] init];
            [alert setMessageText:@"No domain has been configured yet. Do you want to configure it now?"];
            [alert setInformativeText:@"A domain must be configured to allow automatic lookup of remote virtual devices."];
            NSButton *yesBtn = [alert addButtonWithTitle:@"Yes"];
            NSButton *laterBtn = [alert addButtonWithTitle:@"Not now"];
            NSButton *neverBtn = [alert addButtonWithTitle:@"Do not ask again"];
            [[alert window] setInitialFirstResponder:yesBtn];
            [laterBtn setKeyEquivalent:@"\033"];
            [neverBtn setKeyEquivalentModifierMask:NSEventModifierFlagOption];
            [neverBtn setKeyEquivalent:@"\033"];
            NSModalResponse mr = [alert runModal];
            if (mr == NSAlertFirstButtonReturn) {
                /* yes! */
                [self configureDomain];
            } else if (mr == NSAlertSecondButtonReturn) {
                /* not now */
                no_mdns = 0;
                [self autoStartDaemonIfRequired];
            } else {
                /* don't ask again */
                CFPreferencesSetAppValue(CFSTR("Domain"), CFSTR(""), APPID);
                CFPreferencesAppSynchronize(APPID);
                no_mdns = 0;
                [self autoStartDaemonIfRequired];
            }
            [self startCheckTimer];
            return;
        }
        
        if (CFEqual(usbfluxDomain, CFSTR(""))) {
            /* mDNS mode */
            CFRelease(usbfluxDomain);
            no_mdns = 0;
            [self autoStartDaemonIfRequired];
            [self startCheckTimer];
            return;
        }
        
        no_mdns = 1;
        if ([self isRunning]) {
            [NSThread detachNewThreadSelector:@selector(stopUSBFluxDaemon) toTarget:self withObject:nil];
        }

        [self startCheckTimer];

        NSString *domain = nil;
        NSString *scheme = nil;
        [self parseDomain:(__bridge NSString*)usbfluxDomain domainOut:&domain schemeOut:&scheme];
        CFRelease(usbfluxDomain);
        
        CFStringRef proto = nil;
        if ([scheme isEqualToString:@"https"]) {
            proto = kSecAttrProtocolHTTPS;
        } else if ([scheme isEqualToString:@"http"]) {
            proto = kSecAttrProtocolHTTP;
        } else {
            proto = kSecAttrProtocolHTTPS;
        }

        if (!proto) {
            CFPreferencesSetAppValue(CFSTR("Domain"), nil, APPID);
            CFPreferencesAppSynchronize(APPID);
            NSAlert *alert = [[NSAlert alloc] init];
            [alert setMessageText:[NSString stringWithFormat:@"Unsupported protocol '%@'", scheme]];
            [alert setInformativeText:@"Please restart the app to reconfigure."];
            [alert setAlertStyle:NSAlertStyleCritical];
            [alert runModal];
            return;
        }
        
        CFTypeRef check_keys[] = { kSecClass, kSecAttrServer, kSecAttrProtocol, kSecMatchLimit, kSecReturnData, kSecReturnAttributes };
        CFTypeRef check_values[] = { kSecClassInternetPassword, (__bridge CFStringRef)domain, proto, kSecMatchLimitOne, kCFBooleanTrue, kCFBooleanTrue };
        CFDictionaryRef query = CFDictionaryCreate(kCFAllocatorDefault, check_keys, check_values, 6, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        CFTypeRef pwData = NULL;
        OSStatus status = SecItemCopyMatching(query, &pwData);
        CFRelease(query);
        NSString *username = nil;
        NSString *password = nil;
        if (status == errSecSuccess) {
            NSDictionary *creds = (__bridge NSDictionary*)pwData;
            username = [creds objectForKey:(__bridge NSString*)kSecAttrAccount];
            NSData *passwd = [creds objectForKey:(__bridge NSString*)kSecValueData];
            password = (passwd) ? [[NSString alloc] initWithData:passwd encoding:NSUTF8StringEncoding] : nil;
        }
        if (pwData) {
            CFRelease(pwData);
        }
        
        NSMutableDictionary *options = [[NSMutableDictionary alloc] init];
        [options setObject:domain forKey:@"domain"];
        [options setObject:scheme forKey:@"protocol"];
        if (username) [options setObject:username forKey:@"username"];
        if (password) [options setObject:password forKey:@"password"];
        [options setObject:@"runTryLogin:" forKey:@"onError"];
        [self doTryLogin:options];
    }
}

- (void)applicationWillTerminate:(NSNotification *)aNotification
{
    [checkTimer invalidate];

    if ([self isRunning]) {
        NSAlert* alert = [[NSAlert alloc] init];
        [alert setAlertStyle:NSAlertStyleWarning];
        NSButton *btnYes = [alert addButtonWithTitle:@"Yes"];
        [btnYes setTag:1];
        NSButton *btnNo = [alert addButtonWithTitle:@"No"];
        [btnNo setTag:2];
        [alert setMessageText:@"USBFlux is still running"];
        [alert setInformativeText:@"Do you want to stop USBFlux now? If \"No\" is selected, USBFlux will continue to run in the background."];
        BOOL res = [alert runModal];
        if (res == 1) {
            [self stopUSBFluxDaemon];
        }
    }
    free(usbfluxd_path);
    usbfluxd_path = NULL;
}

- (BOOL)applicationShouldHandleReopen:(NSApplication *)theApplication hasVisibleWindows:(BOOL)flag
{
    [self.window setIsVisible:YES];
    return YES;
}

-(IBAction)startStopClicked:(NSButton*)control
{
    self.startStopButton.enabled = NO;
    self.cbAutoStart.focusRingType = NSFocusRingTypeNone;
    if (self.startStopButton.tag == 1) {
        [NSThread detachNewThreadSelector:@selector(stopUSBFluxDaemon) toTarget:self withObject:nil];
    } else {
        [NSThread detachNewThreadSelector:@selector(startUSBFluxDaemon) toTarget:self withObject:nil];
    }
}

-(BOOL)windowShouldClose:(NSWindow *)sender
{
    [self.window setIsVisible:NO];
    return NO;
}

- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication *)theApplication
{
    return YES;
}

-(IBAction)autoStartClicked:(id)sender
{
    CFPreferencesSetAppValue(CFSTR("AutoStart"), (self.cbAutoStart.state == NSControlStateValueOn) ? kCFBooleanTrue : kCFBooleanFalse, APPID);
    CFPreferencesAppSynchronize(APPID);
}
@end
