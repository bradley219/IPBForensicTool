//
//  FSBackupPackage.m
//  IPB Forensic Scanner
//
//  Created by Bradley Snyder on 12/1/13.
//  Copyright (c) 2013 Bradley Snyder. All rights reserved.
//

#import "FSBackupPackage.h"

#define INFO_PLIST_FILENAME @"Info.plist"

@interface FSBackupPackage()

@property (readwrite) FSManifestDB *manifestDB;

@end

@implementation FSBackupPackage

+ (FSBackupPackage*)backupPackageWithBaseURL:(NSURL*)url
{
    FSBackupPackage *bp = [[FSBackupPackage alloc]init];
    bp.baseURL = url;
    return bp;
}

- (id)init
{
    self = [super init];
    _baseURL = nil;
    _manifestDB = [[FSManifestDB alloc]init];
    _manifestDB.backupPackage = self;
    return self;
}

- (BOOL)scan
{
    BOOL success = NO;
    
    @try {
        [_manifestDB scan];

        success = [self getInfo];
        
    }
    @catch (NSException *exception) {
        success = NO;
    }
    
    return success;
}

- (BOOL)getInfo
{
    NSURL *infoURL = [self.baseURL URLByAppendingPathComponent:INFO_PLIST_FILENAME];
    NSDictionary *rootDict = [[NSDictionary alloc]initWithContentsOfURL:infoURL];
    
    self.deviceName = [rootDict objectForKey:@"Device Name"];
    self.backupDate = [rootDict objectForKey:@"Last Backup Date"];
    
    return YES;
}

- (BOOL)extractToURL:(NSURL *)url symlink:(BOOL)symlink
{
    return [_manifestDB extractToURL:url symlink:symlink];
}

@end
