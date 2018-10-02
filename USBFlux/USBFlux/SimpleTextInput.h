//
//  SimpleTextInput.h
//  USBFlux
//
//  Created by Nikias Bassen on 27.09.18.
//  Copyright © 2018 Corellium. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>

@interface SimpleTextInput : NSAlert <NSTextFieldDelegate, NSWindowDelegate>
-(NSString*)textValue;
-(void)setTextValue:(NSString*)value;
-(void)setPlaceholder:(NSString*)text;
@end
