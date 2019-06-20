//
//  Corellium.h
//  USBFlux
//
//  Created by Nikias Bassen on 26.09.18.
//  Copyright © 2018 Corellium. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface Corellium : NSObject <NSURLConnectionDelegate>
@property (nonatomic, copy) NSString* domain;
- (id)initWithDomain:(NSString *)domain username:(NSString *)u password:(NSString *)p totp:(NSString *)totp;
-(BOOL)login:(NSError**)error;
-(id)projects:(NSError**)error;
-(id)instances:(NSError**)error;
-(id)instances:(NSError**)error withQuery:(NSString*)query;
@end
