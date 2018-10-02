//
//  PasswordEntry.m
//  USBFlux
//
//  Created by Nikias Bassen on 26.09.18.
//  Copyright © 2018 Corellium. All rights reserved.
//

#import "PasswordEntry.h"

@interface PasswordEntry ()
{
    NSTextField *inputUser;
    NSSecureTextField *inputPass;
    NSButton *okBtn;
    NSButton *cancelBtn;
}
@end

@implementation PasswordEntry
-(id)init {
    self = [super init];
    if (!self) {
        return nil;
    }

    [self setMessageText:@"Enter username and password"];
    NSView *group = [[NSView alloc] initWithFrame:NSMakeRect(0,0,200,60)];
    inputUser = [[NSTextField alloc] initWithFrame:NSMakeRect(0, 32, 200, 24)];
    [inputUser setStringValue:@""];
    if (@available(macOS 10.10, *)) {
        [inputUser setPlaceholderString:@"username"];
    }
    inputPass = [[NSSecureTextField alloc] initWithFrame:NSMakeRect(0, 0, 200, 24)];
    [inputPass setStringValue:@""];
    if (@available(macOS 10.10, *)) {
        [inputPass setPlaceholderString:@"password"];
    }
    [group addSubview:inputUser];
    [group addSubview:inputPass];
    okBtn = [self addButtonWithTitle:@"OK"];
    cancelBtn = [self addButtonWithTitle:@"Cancel"];
    [self setAccessoryView:group];
    [inputUser setDelegate:self];
    [inputPass setDelegate:self];
    [[self window] setInitialFirstResponder:inputUser];
    okBtn.enabled = NO;
    return self;
}

- (BOOL)control:(NSControl*)control textView:(NSTextView*)textView doCommandBySelector:(SEL)commandSelector
{
    BOOL result = NO;
    if (commandSelector == @selector(insertNewline:)) {
        if (control == inputUser) {
            [[self window] makeFirstResponder:inputPass];
            result = YES;
        }
    }
    else if (commandSelector == @selector(insertTab:)) {
    }
    return result;
}

- (void)controlTextDidChange:(NSNotification *)obj {
    okBtn.enabled = (inputUser.stringValue.length > 0 && inputPass.stringValue.length > 0);
}

- (void)windowDidBecomeKey:(NSNotification *)notification {
    [[self window] setAutorecalculatesKeyViewLoop:NO];
    [inputUser setNextKeyView:inputPass];
    [inputPass setNextKeyView:okBtn];
    [okBtn setNextKeyView:cancelBtn];
    [cancelBtn setNextKeyView:inputUser];
    if (inputUser.stringValue.length > 0) {
        [[self window] makeFirstResponder:inputPass];
    }
}

- (void)setUserValue:(NSString*)value {
    [inputUser setStringValue:((value) ? value : @"")];
}

- (NSString*)userValue {
    return [inputUser stringValue];
}

- (NSString*)passValue {
    return [inputPass stringValue];
}
@end
