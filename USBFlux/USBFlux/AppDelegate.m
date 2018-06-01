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
#include <sys/socket.h>
#include <sys/un.h>

static AuthorizationRef authorization = nil;
static BOOL wasRunning = YES;

@interface AppDelegate ()
{
    NSTimer *checkTimer;
    NSTask *usbfluxdTask;
    char *usbfluxd_path;
}
@property (weak) IBOutlet NSTextField *statusLabel;
@property (weak) IBOutlet NSTextField *detailLabel;
@property (weak) IBOutlet NSWindow *window;
@property (weak) IBOutlet NSButton *startStopButton;
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
    if (chmod(usbfluxd_path, 0755) != 0) {
        if (authorization) {
            char *command = "/bin/chmod";
            char *args[] = { "755", usbfluxd_path, NULL };
            [self runCommandWithAuth:authorization command:command arguments:args];
        }
    }
}

- (BOOL)checkUSBFluxDaemonPermissions
{
    BOOL result = NO;
    struct stat fst;
    bzero(&fst, sizeof(struct stat));
    if (stat(usbfluxd_path, &fst) == 0) {
        if ((fst.st_uid == 0) && (fst.st_mode == 0755)) {
            result = YES;
        }
    }
    return result;
}

-(void)startUSBFluxDaemon
{
    if (!authorization) {
        authorization = [self getAuth:@"USBFlux needs elevated permissions to start."];
    }
    if (!authorization) {
        NSAlert* alert = [[NSAlert alloc] init];
        [alert setAlertStyle:NSAlertStyleWarning];
        [alert addButtonWithTitle:@"OK"];
        [alert setMessageText:@"Missing Permissions"];
        [alert setInformativeText:@"USBFlux cannot be started without elevated privileges."];
        [alert runModal];
        return;
    }
    
    if (![self checkUSBFluxDaemonPermissions]) {
        [self fixupUSBFluxDaemonPermissions];
    }
    
    char *command = usbfluxd_path;
    char *args[] = { "-v", NULL };
    [self runCommandWithAuth:authorization command:command arguments:args];
}

-(void)stopUSBFluxDaemon
{
    if (!authorization) {
        authorization = [self getAuth:@"USBFlux needs elevated permissions to stop."];
    }
    if (!authorization) {
        NSAlert* alert = [[NSAlert alloc] init];
        [alert setAlertStyle:NSAlertStyleWarning];
        [alert addButtonWithTitle:@"OK"];
        [alert setMessageText:@"Missing Permissions"];
        [alert setInformativeText:@"USBFlux cannot be stopped without elevated privileges."];
        [alert runModal];
        return;
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
    
    if (pid > 0) {
        char pid_s[10];
        sprintf(pid_s, "%d", pid);
        char *command = "/bin/kill";
        char *args[] = { pid_s, NULL };
        [self runCommandWithAuth:authorization command:command arguments:args];
    } else {
        char *command = "/usr/bin/killall";
        char *args[] = { "usbfluxd", NULL };
        [self runCommandWithAuth:authorization command:command arguments:args];
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
    NSDictionary *instances = [self getInstances];
    if (!timer) {
        wasRunning = (instances == nil);
    }
    if (instances) {
        self.statusLabel.stringValue = @"USBFlux is running.";
        self.startStopButton.title = @"Stop";
        self.startStopButton.tag = 1;
        if (!wasRunning) {
            self.startStopButton.enabled = YES;
        }
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
        wasRunning = YES;
    } else {
        self.statusLabel.stringValue = @"USBFlux is not running.";
        self.startStopButton.title = @"Start";
        self.startStopButton.tag = 0;
        if (wasRunning) {
            self.startStopButton.enabled = YES;
        }
        self.detailLabel.hidden = YES;
        wasRunning = NO;
    }
}

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification
{
    [[NSApp mainWindow] setDelegate:self];
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
        [self checkStatus:nil];
        checkTimer = [NSTimer scheduledTimerWithTimeInterval:1.0 target:self selector:@selector(checkStatus:) userInfo:nil repeats:YES];
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
        [alert setMessageText:@"USBFlux still running"];
        [alert setInformativeText:@"USBFlux is still running. Do you want to stop USBFlux now? Otherwise it will continue to run in the background despite this app being closed."];
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

@end
