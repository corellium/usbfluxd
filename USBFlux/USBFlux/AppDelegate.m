//
//  AppDelegate.m
//  USBFlux
//
//  Created by Nikias Bassen on 30.05.18.
//  Copyright © 2018 Corellium. All rights reserved.
//

#import "AppDelegate.h"
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
    NSTask *usbfluxdTask;
    char *usbfluxd_path;
    char *terminate_path;
}
@property (weak) IBOutlet NSTextField *statusLabel;
@property (weak) IBOutlet NSTextField *detailLabel;
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
    char *argv[] = { usbfluxd_path, "-v", NULL };
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
    id result = nil;

    int sfd = socket_connect_unix("/var/run/usbmuxd");
    if (sfd < 0) {
        return nil;
    }

    const char req_xml[] = "<plist version=\"1.0\"><dict><key>MessageType</key><string>Instances</string></dict></plist>";
    char buf[65536];
    
    struct usbmuxd_header muxhdr;
    muxhdr.length = sizeof(struct usbmuxd_header) + sizeof(req_xml);
    muxhdr.version = 1;
    muxhdr.message = 8;
    muxhdr.tag = 0;
    
    if (send(sfd, &muxhdr, sizeof(struct usbmuxd_header), 0) == sizeof(struct usbmuxd_header)) {
        if (send(sfd, req_xml, sizeof(req_xml), 0) == sizeof(req_xml)) {
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
                        NSDictionary *instances = (dict) ? [dict objectForKey:@"Instances"] : nil;
                        if (instances) {
                            result = instances;
                        }
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

- (void)checkStatus:(NSTimer*)timer
{
    if (![self.window isVisible]) {
        return;
    }
    NSDictionary *instances = [self getInstances];
    if (instances) {
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
        self.detailLabel.stringValue = [NSString stringWithFormat:@"%d Instance%s (%d Local / %d Remote)\n%d Device%s (%d Local / %d Remote)", local_count+remote_count,  (local_count+remote_count == 1) ? "" : "s", local_count, remote_count, local_devices+remote_devices, (local_devices+remote_devices == 1) ? "" : "s", local_devices, remote_devices];
        self.detailLabel.hidden = NO;
    } else {
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
}

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification
{
    [[NSApp mainWindow] setDelegate:self];
    self.cbAutoStart.focusRingType = NSFocusRingTypeNone;
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
        [self checkStatus:nil];
        checkTimer = [NSTimer scheduledTimerWithTimeInterval:1.0 target:self selector:@selector(checkStatus:) userInfo:nil repeats:YES];

        CFPreferencesAppSynchronize(CFSTR("com.corellium.USBFlux"));
        Boolean existsAndValid = NO;
        Boolean shouldAutoStart = CFPreferencesGetAppBooleanValue(CFSTR("AutoStart"), CFSTR("com.corellium.USBFlux"), &existsAndValid);
        if (existsAndValid && shouldAutoStart) {
            self.cbAutoStart.state = NSControlStateValueOn;
            if (![self isRunning]) {
                self.startStopButton.enabled = NO;
                [NSThread detachNewThreadSelector:@selector(startUSBFluxDaemon) toTarget:self withObject:nil];
            }
        }
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
    CFPreferencesSetAppValue(CFSTR("AutoStart"), (self.cbAutoStart.state == NSControlStateValueOn) ? kCFBooleanTrue : kCFBooleanFalse, CFSTR("com.corellium.USBFlux"));
    CFPreferencesAppSynchronize(CFSTR("com.corellium.USBFlux"));
}
@end
