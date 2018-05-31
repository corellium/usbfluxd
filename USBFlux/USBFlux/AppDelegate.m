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

static AuthorizationRef authorization = nil;
static BOOL wasRunning = YES;

@interface AppDelegate ()
{
    NSTimer *checkTimer;
    NSTask *usbfluxdTask;
    char *usbfluxd_path;
}
@property (weak) IBOutlet NSTextField *statusLabel;
@property (weak) IBOutlet NSWindow *window;
@property (weak) IBOutlet NSButton *startStopButton;
@end

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

static BOOL usbfluxdPermissionsChecked = NO;

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
    char *args[] = { "-vvv", NULL };
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
    char *command = "/usr/bin/killall";
    char *args[] = { "usbfluxd", NULL };
    [self runCommandWithAuth:authorization command:command arguments:args];
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

- (void)checkStatus:(NSTimer*)timer
{
    if ([self isRunning]) {
        self.statusLabel.stringValue = @"USBFlux is running.";
        self.startStopButton.title = @"Stop";
        self.startStopButton.tag = 1;
        if (!wasRunning) {
            self.startStopButton.enabled = YES;
        }
        wasRunning = YES;
    } else {
        self.statusLabel.stringValue = @"USBFlux is not running.";
        self.startStopButton.title = @"Start";
        self.startStopButton.tag = 0;
        if (wasRunning) {
            self.startStopButton.enabled = YES;
        }
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
