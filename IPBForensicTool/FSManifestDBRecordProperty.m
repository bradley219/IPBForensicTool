//
//  FSManifestDBRecordProperty.m
//  IPB Forensic Scanner
//
//  Created by Bradley Snyder on 12/1/13.
//  Copyright (c) 2013 Bradley Snyder. All rights reserved.
//

#import "FSManifestDBRecordProperty.h"
#import "FSFileUtils.h"

@interface FSManifestDBRecordProperty()

@property (readwrite) NSString *name;
@property (readwrite) NSString *value;

@end

@implementation FSManifestDBRecordProperty

- (id)init
{
    self = [super init];
    _name = nil;
    _value = nil;
    _record = nil;
    return self;
}

- (void)parseFromFile:(NSFileHandle*)fileHandle
{
    _name = [FSFileUtils parseNextString:fileHandle];
    _value = [FSFileUtils parseNextString:fileHandle];
}

@end
