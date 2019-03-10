//
//  Corellium.m
//  USBFlux
//
//  Created by Nikias Bassen on 26.09.18.
//  Copyright © 2018 Corellium. All rights reserved.
//

#import "Corellium.h"
#import "STHTTPRequest.h"

@interface Corellium ()
{
    NSString *username;
    NSString *password;
    NSString* endpoint;
    id token;
}
@end

@implementation Corellium

- (id)initWithDomain:(NSString*)domain username:(NSString*)u password:(NSString*)p
{
    self = [super init];
    if (self) {
        endpoint = [NSString stringWithFormat:@"%@/api/v1", domain];
        self.domain = domain;
        username = u;
        password = p;
    }
    return self;
}

-(id)getToken:(NSError**)error
{
    if (token) {
        NSString *expiration = [token objectForKey:@"expiration"];
        if (expiration) {
            NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
            [formatter setDateFormat:@"yyyy-MM-dd'T'HH:mm:ss.SSSSSS'Z'"];
            [formatter setLocale:[[NSLocale alloc] initWithLocaleIdentifier:@"en_US_POSIX"]];
            NSDate *expire_date = [formatter dateFromString:expiration];
            NSDate *soon_date = [NSDate dateWithTimeIntervalSinceNow:15*60];
            if ([expire_date isGreaterThan:soon_date]) {
                return token;
            }
        }
        token = nil;
    }
    
    NSMutableDictionary *requestDict = [NSMutableDictionary dictionary];
    [requestDict setObject:username forKey:@"username"];
    [requestDict setObject:password forKey:@"password"];
    
    STHTTPRequest *request = [STHTTPRequest requestWithURLString:[NSString stringWithFormat:@"%@/tokens", endpoint]];
    [request setHTTPMethod:@"POST"];
    [request setHeaderWithName:@"Content-Type" value:@"application/json"];
    [request setHeaderWithName:@"Accept" value:@"application/json"];
    request.POSTDictionary = requestDict;

    NSString *response = nil;
    NSError *err = nil;
    response = [request startSynchronousSessionWithError:&err];
    
    if (!response) {
        NSLog(@"ERROR: %@", err);
        if (error) {
            *error = err;
        }
        return nil;
    }
    
    NSDictionary *json = [NSJSONSerialization JSONObjectWithData:[response dataUsingEncoding:NSUTF8StringEncoding] options:0 error:&err];
    if (json && [json objectForKey:@"token"]) {
        token = json;
    } else {
        if (error) {
            *error = err;
        }
        token = nil;
    }
    return token;
}

-(BOOL)login:(NSError**)error
{
    token = nil;
    return ([self getToken:error]) ? YES : NO;
}

-(id)projects:(NSError**)error
{
    NSDictionary *token = [self getToken:error];
    NSString *token_token = (token) ? [token objectForKey:@"token"] : nil;
    if (!token || !token_token) {
        NSLog(@"ERROR: projects: invalid token");
        return nil;
    }
    
    STHTTPRequest *request = [STHTTPRequest requestWithURLString:[NSString stringWithFormat:@"%@/projects", endpoint]];
    [request setHeaderWithName:@"Authorization" value:token_token];
    [request setHeaderWithName:@"Accept" value:@"application/json"];
    NSString *response = nil;
    NSError *err = nil;
    response = [request startSynchronousSessionWithError:&err];
    
    if (err) {
        if (error) {
            *error = err;
        }
        return nil;
    }
    
    id json = [NSJSONSerialization JSONObjectWithData:[response dataUsingEncoding:NSUTF8StringEncoding] options:0 error:&err];
    if (!json) {
        NSLog(@"failed to parse response while getting list of projects");
        return nil;
    }
    if (![json isKindOfClass:[NSArray class]]) {
        NSString *errstr = [json objectForKey:@"error"];
        if (errstr) {
            NSLog(@"failed to get list of projects: %@", errstr);
            return nil;
        } else {
            NSLog(@"failed to get list of projects: unexpected result: %@", json);
        }
    }
    return json;
}

-(id)instances:(NSError**)error
{
    return [self instances:error withQuery:nil];
}

-(id)instances:(NSError**)error withQuery:(NSString*)query
{
    NSDictionary *token = [self getToken:error];
    NSString *token_token = (token) ? [token objectForKey:@"token"] : nil;
    if (!token || !token_token) {
        NSLog(@"ERROR: instances:withQuery: invalid token");
        return nil;
    }
    
    STHTTPRequest *request = [STHTTPRequest requestWithURLString:[NSString stringWithFormat:@"%@/instances%@%@", endpoint, (query) ? @"?" : @"", (query) ? query : @""]];
    [request setHeaderWithName:@"Authorization" value:token_token];
    [request setHeaderWithName:@"Accept" value:@"application/json"];
    
    NSString *response = nil;
    NSError *err = nil;
    response = [request startSynchronousSessionWithError:&err];
    
    if (err) {
        if (error) {
            *error = err;
        }
        return nil;
    }
    id json = [NSJSONSerialization JSONObjectWithData:[response dataUsingEncoding:NSUTF8StringEncoding] options:0 error:&err];
    if (!json) {
        NSLog(@"failed to parse response while getting list of instances");
        return nil;
    }
    if (![json isKindOfClass:[NSArray class]]) {
        NSString *errstr = [json objectForKey:@"error"];
        if (errstr) {
            NSLog(@"failed to get list of instances: %@", errstr);
            return nil;
        } else {
            NSLog(@"failed to get list of instances: unexpected result: %@", json);
            return nil;
        }
    }
    return json;
}
@end
