//
//  FSManifestDBRecord.h
//  IPB Forensic Scanner
//
//  Created by Bradley Snyder on 12/1/13.
//  Copyright (c) 2013 Bradley Snyder. All rights reserved.
//

#import <Foundation/Foundation.h>

@class FSManifestDB;

@interface FSManifestDBRecord : NSObject

@property (readonly) NSString *sha1;
@property (readonly) NSString *domain;
@property (readonly) NSString *path;
@property (readonly) NSString *linkTarget;
@property (readonly) NSString *dataHash;
@property (readonly) NSString *encryptKey;
@property (readonly) uint16_t mode;
@property (readonly) uint32_t unknown;
@property (readonly) uint32_t inode;
@property (readonly) uint32_t uid;
@property (readonly) uint32_t gid;
@property (readonly) uint32_t mtime;
@property (readonly) uint32_t atime;
@property (readonly) uint32_t ctime;
@property (readonly) uint64_t length;
@property (readonly) uint8_t protectionclass;
@property (readonly) NSArray *properties;
@property (readonly) BOOL isDirectory;
@property (readonly) BOOL fileExists;

@property FSManifestDB *manifestDB;

- (void)parseFromFile:(NSFileHandle*)fileHandle;
- (BOOL)extractToURL:(NSURL*)url symlink:(BOOL)symlink;
- (BOOL)copyFileToExactPath:(NSURL*)path;

@end
