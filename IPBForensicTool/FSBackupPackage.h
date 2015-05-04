//
//  FSBackupPackage.h
//  IPB Forensic Scanner
//
//  Created by Bradley Snyder on 12/1/13.
//  Copyright (c) 2013 Bradley Snyder. All rights reserved.
//

#import <Foundation/Foundation.h>

@class FSManifestDB;

@interface FSBackupPackage : NSObject

@property (readonly) FSManifestDB *manifestDB;
@property NSURL *baseURL;
@property NSString *deviceName;
@property NSDate *backupDate;

+ (FSBackupPackage*)backupPackageWithBaseURL:(NSURL*)url;
- (BOOL)scan;
- (BOOL)extractToURL:(NSURL*)url symlink:(BOOL)symlink;

@end

#import "FSManifestDB.h"
