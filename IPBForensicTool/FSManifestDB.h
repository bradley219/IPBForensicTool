//
//  FSManifestDB.h
//  IPB Forensic Scanner
//
//  Created by Bradley Snyder on 12/1/13.
//  Copyright (c) 2013 Bradley Snyder. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "FSManifestDBRecord.h"

@class FSBackupPackage;

@interface FSManifestDB : NSObject

@property FSBackupPackage *backupPackage;
@property NSArray *records;

- (void)scan;
- (BOOL)extractToURL:(NSURL*)url symlink:(BOOL)symlink;
- (FSManifestDBRecord*)searchRecordWithDomain:(NSString*)domain path:(NSString*)path;

@end

#import "FSBackupPackage.h"
