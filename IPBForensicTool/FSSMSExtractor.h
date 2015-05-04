//
//  FSSMSExtractor.h
//  IPB Forensic Scanner
//
//  Created by Bradley Snyder on 2/20/14.
//  Copyright (c) 2014 Bradley Snyder. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "FSManifestDB.h"


@interface FSSMSExtractor : NSObject

@property NSArray *handleIDs;

- (id)initWithManifest:(FSManifestDB*)manifest;
- (BOOL)parse;

- (BOOL)extractForHandleID:(NSString*)handleID;

@end
