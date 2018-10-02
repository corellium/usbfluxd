//
//  SimpleTextInput.m
//  USBFlux
//
//  Created by Nikias Bassen on 27.09.18.
//  Copyright © 2018 Corellium. All rights reserved.
//

#import "SimpleTextInput.h"

@interface SimpleTextInput ()
{
    NSTextField *inputField;
    NSButton *okBtn;
    NSButton *cancelBtn;
}
@end

@implementation SimpleTextInput
-(id)init {
    self = [super init];
    if (!self) {
        return nil;
    }
    
    inputField = [[NSTextField alloc] initWithFrame:NSMakeRect(0, 32, 200, 24)];
    [inputField setStringValue:@""];
    [inputField setDelegate:self];
    okBtn = [self addButtonWithTitle:@"OK"];
    cancelBtn = [self addButtonWithTitle:@"Cancel"];
    [self setAccessoryView:inputField];
    [[self window] setInitialFirstResponder:inputField];
    okBtn.enabled = NO;
    return self;
}

- (void)controlTextDidChange:(NSNotification *)obj {
    okBtn.enabled = (inputField.stringValue.length > 0);
}

- (void)windowDidBecomeKey:(NSNotification *)notification {
    [[self window] setAutorecalculatesKeyViewLoop:NO];
    [inputField setNextKeyView:okBtn];
    [okBtn setNextKeyView:cancelBtn];
    [cancelBtn setNextKeyView:inputField];
}

- (NSString*)textValue {
    return [inputField stringValue];
}

- (void)setTextValue:(NSString *)value
{
    [inputField setStringValue:((value) ? value : @"")];
}

- (void)setPlaceholder:(NSString *)text
{
    if (@available(macOS 10.10, *)) {
        [inputField setPlaceholderString:(text) ? text : @""];
    }
}
@end
