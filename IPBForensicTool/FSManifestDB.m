//
//  FSManifestDB.m
//  IPB Forensic Scanner
//
//  Created by Bradley Snyder on 12/1/13.
//  Copyright (c) 2013 Bradley Snyder. All rights reserved.
//

#import "FSManifestDB.h"
#import "constants.h"

#define MANIFEST_DB_FILENAME @"Manifest.mbdb"

static NSUInteger manifestDBSignatureLength = 6;
static char *manifestDBSignature = "mbdb\x5\x0";

@interface FSManifestDB()

@end

@implementation FSManifestDB

- (id)init
{
    self = [super init];
    return self;
}

- (void)scan
{
    [self parse];
}

- (void)parse
{
    _records = [[NSArray alloc]init];
    NSURL *manifestDBURL = [_backupPackage.baseURL URLByAppendingPathComponent:MANIFEST_DB_FILENAME];
    
    NSError *e = nil;
    BOOL reachable = [manifestDBURL checkResourceIsReachableAndReturnError:&e];
    if( !reachable )
    {
        [NSException raise:PARSING_ERROR_EXCEPTION_NAME format:MANIFEST_DB_FILENAME @" not found in directory"];
    }
    else
    {
        NSError *fhe = nil;
        NSFileHandle *fh = [NSFileHandle fileHandleForReadingFromURL:manifestDBURL error:&fhe];
        if( fh == nil )
        {
            [NSException raise:PARSING_ERROR_EXCEPTION_NAME format:MANIFEST_DB_FILENAME @" cannot be read"];
        }
        else
        {
            [self read:fh];
            [fh closeFile];
        }
    }
}

- (void)read:(NSFileHandle*)manifestDBHandle
{
    [manifestDBHandle seekToEndOfFile];
    unsigned long long fileLength = [manifestDBHandle offsetInFile];
    [manifestDBHandle seekToFileOffset:0];
    
    NSData *expectedSignature = [NSData dataWithBytes:manifestDBSignature length:manifestDBSignatureLength];
    NSData *signature = [manifestDBHandle readDataOfLength:manifestDBSignatureLength];
    
    BOOL sigMatch = [signature isEqualToData:expectedSignature];
    if( !sigMatch )
    {
        [NSException raise:PARSING_ERROR_EXCEPTION_NAME format:@"Manifest DB file signature is incorrect"];
    }
    
    NSMutableArray *records = [[NSMutableArray alloc]init];
    while( [manifestDBHandle offsetInFile] < fileLength )
    {
        FSManifestDBRecord *record = [[FSManifestDBRecord alloc]init];
        record.manifestDB = self;
        [record parseFromFile:manifestDBHandle];
        [records addObject:record];
    }
    _records = records;
}

- (BOOL)extractToURL:(NSURL *)url symlink:(BOOL)symlink
{
    NSInteger errorCount = 0;
    for( FSManifestDBRecord *record in _records )
    {
        @try {
            [record extractToURL:url symlink:symlink];
        }
        @catch (NSException *exception) {
            errorCount++;
        }
    }
    return YES;
}

- (FSManifestDBRecord*)searchRecordWithDomain:(NSString *)domain path:(NSString *)path
{
    FSManifestDBRecord *found = nil;
    for( FSManifestDBRecord *record in _records )
    {
        if( [record.domain isEqualToString:domain] && [record.path isEqualToString:path] )
        {
            found = record;
            break;
        }
    }
    return found;
}

@end
