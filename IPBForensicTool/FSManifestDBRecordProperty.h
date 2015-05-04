//
//  FSManifestDBRecordProperty.h
//  IPB Forensic Scanner
//
//  Created by Bradley Snyder on 12/1/13.
//  Copyright (c) 2013 Bradley Snyder. All rights reserved.
//

#import <Foundation/Foundation.h>

@class FSManifestDBRecord;

@interface FSManifestDBRecordProperty : NSObject

@property (readonly) NSString *name;
@property (readonly) NSString *value;
@property FSManifestDBRecord *record;

- (id)init;
- (void)parseFromFile:(NSFileHandle*)fileHandle;

@end
