//
//  FSUtils.m
//  IPB Forensic Scanner
//
//  Created by Bradley Snyder on 12/1/13.
//  Copyright (c) 2013 Bradley Snyder. All rights reserved.
//

#import "FSUtils.h"
#include <CommonCrypto/CommonDigest.h>

@implementation FSUtils

+ (NSString*)hexStringFromData:(NSData*)data
{
    NSMutableString *str = [[NSMutableString alloc]initWithCapacity:data.length * 2];
    uint8_t *b = (uint8_t*)data.bytes;
    NSUInteger l = data.length;
    while( l-- )
    {
        [str appendFormat:@"%02x", *b];
        b++;
    }
    return str;
}

+ (NSString*)sha1Digest:(NSString*)string
{
    NSData *input = [string dataUsingEncoding:NSUTF8StringEncoding];
    unsigned char digest[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1(input.bytes, (CC_LONG)input.length, digest);
    NSData *output = [NSData dataWithBytes:digest length:CC_SHA1_DIGEST_LENGTH];
    return [self hexStringFromData:output];
}

@end
