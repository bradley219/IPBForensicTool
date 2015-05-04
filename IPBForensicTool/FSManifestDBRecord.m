//
//  FSManifestDBRecord.m
//  IPB Forensic Scanner
//
//  Created by Bradley Snyder on 12/1/13.
//  Copyright (c) 2013 Bradley Snyder. All rights reserved.
//

#import "FSManifestDBRecord.h"
#import "FSManifestDBRecordProperty.h"
#import "FSManifestDB.h"
#import "FSFileUtils.h"
#import "FSUtils.h"
#import <sys/stat.h>



@interface FSManifestDBRecord()

@property (readwrite) NSString *sha1;
@property (readwrite) NSString *domain;
@property (readwrite) NSString *path;
@property (readwrite) NSString *linkTarget;
@property (readwrite) NSString *dataHash;
@property (readwrite) NSString *encryptKey;
@property (readwrite) uint16_t mode;
@property (readwrite) uint32_t unknown;
@property (readwrite) uint32_t inode;
@property (readwrite) uint32_t uid;
@property (readwrite) uint32_t gid;
@property (readwrite) uint32_t mtime;
@property (readwrite) uint32_t atime;
@property (readwrite) uint32_t ctime;
@property (readwrite) uint64_t length;
@property (readwrite) uint8_t protectionclass;

@property (readwrite) NSArray *properties;
@property (readwrite) BOOL fileExists;
@property BOOL fileChecked;
@property NSURL *resourceURL;

@end

@implementation FSManifestDBRecord
@synthesize fileExists=_fileExists;
@synthesize isDirectory=_isDirectory;

- (id)init
{
    self = [super init];
    _sha1 = nil;
    _domain = nil;
    _path = nil;
    _linkTarget = nil;
    _dataHash = nil;
    _encryptKey = nil;
    _mode = 0;
    _unknown = 0;
    _inode = 0;
    _uid = 0;
    _gid = 0;
    _mtime = 0;
    _atime = 0;
    _ctime = 0;
    _length = 0;
    _protectionclass = 0;
    
    _properties = [[NSArray alloc]init];
    _fileExists = NO;
    _fileChecked = NO;
    _resourceURL = nil;
    
    _manifestDB = nil;
    return self;
}

- (void)parseFromFile:(NSFileHandle*)fileHandle
{
    _domain = [FSFileUtils parseNextString:fileHandle];
    _path = [FSFileUtils parseNextString:fileHandle];
    _linkTarget = [FSFileUtils parseNextString:fileHandle];
    _dataHash = [FSFileUtils parseNextString:fileHandle];
    _encryptKey = [FSFileUtils parseNextString:fileHandle];
    
    _mode = [FSFileUtils parseNextInt16:fileHandle];
    _unknown = [FSFileUtils parseNextInt32:fileHandle];
    _inode = [FSFileUtils parseNextInt32:fileHandle];
    _uid = [FSFileUtils parseNextInt32:fileHandle];
    _gid = [FSFileUtils parseNextInt32:fileHandle];
    _mtime = [FSFileUtils parseNextInt32:fileHandle];
    _atime = [FSFileUtils parseNextInt32:fileHandle];
    _ctime = [FSFileUtils parseNextInt32:fileHandle];
    _length = [FSFileUtils parseNextInt64:fileHandle];
    _protectionclass = [FSFileUtils parseNextInt8:fileHandle];
    uint8_t propertycount = [FSFileUtils parseNextInt8:fileHandle];
    
    _sha1 = [FSUtils sha1Digest:[_domain stringByAppendingFormat:@"-%@", _path]];
    
    NSMutableArray *props = [[NSMutableArray alloc]initWithCapacity:propertycount];
    for( int i = 0; i < propertycount; i++ )
    {
        FSManifestDBRecordProperty *property = [[FSManifestDBRecordProperty alloc]init];
        property.record = self;
        [property parseFromFile:fileHandle];
        [props addObject:property];
    }
    _properties = props;
}

- (void)checkFile
{
    _fileExists = NO;
    if( _manifestDB.backupPackage.baseURL && _sha1 )
    {
        _resourceURL = [_manifestDB.backupPackage.baseURL URLByAppendingPathComponent:_sha1];
        _fileExists = [_resourceURL checkResourceIsReachableAndReturnError:nil];
    }
}

- (BOOL)fileExists
{
    if( !_fileChecked )
    {
        [self checkFile];
        _fileChecked = YES;
    }
    return _fileExists;
}

- (void)setFileExists:(BOOL)fileExists
{
    _fileExists = fileExists;
}

- (BOOL)isDirectory
{
    return S_ISDIR(_mode);
}

- (BOOL)copyFileToExactPath:(NSURL *)path
{
    BOOL success = NO;
    if( [self fileExists] )
    {
       success = [[NSFileManager defaultManager]copyItemAtURL:_resourceURL toURL:path error:nil];
    }
    return success;
}

- (BOOL)extractToURL:(NSURL *)url symlink:(BOOL)symlink
{
    BOOL success = YES;
    NSFileManager *fm = [NSFileManager defaultManager];
    
    NSURL *baseURL = [url URLByAppendingPathComponent:_domain];
    NSURL *destURL = [baseURL URLByAppendingPathComponent:_path];
    if( [self isDirectory] )
    {
        [fm createDirectoryAtURL:destURL withIntermediateDirectories:YES attributes:nil error:nil];
    }
    else
    {
        if( [self fileExists] )
        {
            if( symlink )
            {
                [fm createSymbolicLinkAtURL:destURL withDestinationURL:_resourceURL error:nil];
            }
            else
            {
                [fm copyItemAtURL:_resourceURL toURL:destURL error:nil];
            }
        }
        else
        {
            destURL = [baseURL URLByAppendingPathComponent:[_path stringByAppendingString:@"-missing"]];
            NSFileHandle *fh = [NSFileHandle fileHandleForWritingToURL:destURL error:nil];
            [fh closeFile];
        }
    }
    
    return success;
}

@end
