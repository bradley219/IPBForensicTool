//
//  FSFileUtils.m
//  IPB Forensic Scanner
//
//  Created by Bradley Snyder on 12/1/13.
//  Copyright (c) 2013 Bradley Snyder. All rights reserved.
//

#import "FSFileUtils.h"

@implementation FSFileUtils

+ (NSString*)parseNextString:(NSFileHandle*)fileHandle
{
    NSString *string = nil;
    
    uint16_t strLen = [FSFileUtils parseNextInt16:fileHandle];
    if( strLen == 0xffff )
    {
        string = nil;
    }
    else
    {
        NSData *stringData = [fileHandle readDataOfLength:strLen];
        if( stringData.length != strLen )
        {
            [NSException raise:@"parsingError" format:@"expected string data of length %d, got %lu", strLen, stringData.length];
        }
        string = [[NSString alloc]initWithData:stringData encoding:NSUTF8StringEncoding];
    }
    
    return string;
}

+ (uint8_t)parseNextInt8:(NSFileHandle*)fileHandle
{
    NSData *d = [fileHandle readDataOfLength:1];
    if( d.length != 1 )
    {
        [NSException raise:@"parsingError" format:@"expected 1 byte of integer data, got %lu", d.length];
    }
    return *((uint8_t*)d.bytes);
}

+ (uint16_t)parseNextInt16:(NSFileHandle*)fileHandle
{
    NSData *d = [fileHandle readDataOfLength:2];
    if( d.length != 2 )
    {
        [NSException raise:@"parsingError" format:@"expected 2 bytes of integer data, got %lu", d.length];
    }
    uint16_t v = *((uint16_t*)d.bytes);
    return CFSwapInt16BigToHost(v);
}

+ (uint32_t)parseNextInt32:(NSFileHandle*)fileHandle
{
    NSData *d = [fileHandle readDataOfLength:4];
    if( d.length != 4 )
    {
        [NSException raise:@"parsingError" format:@"expected 4 bytes of integer data, got %lu", d.length];
    }
    uint32_t v = *((uint32_t*)d.bytes);
    return CFSwapInt32BigToHost(v);
}

+ (uint64_t)parseNextInt64:(NSFileHandle*)fileHandle
{
    NSData *d = [fileHandle readDataOfLength:8];
    if( d.length != 8 )
    {
        [NSException raise:@"parsingError" format:@"expected 8 bytes of integer data, got %lu", d.length];
    }
    uint64_t v = *((uint64_t*)d.bytes);
    return CFSwapInt64BigToHost(v);
}

@end
