//
//  PasswordEntry.h
//  USBFlux
//
//  Created by Nikias Bassen on 26.09.18.
//  Copyright © 2018 Corellium. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>

@interface PasswordEntry : NSAlert <NSTextFieldDelegate, NSWindowDelegate>
-(void)setUserValue:(NSString*)value;
-(NSString*)userValue;
-(NSString*)passValue;
@end
