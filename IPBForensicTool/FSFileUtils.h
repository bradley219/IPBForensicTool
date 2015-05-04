//
//  FSFileUtils.h
//  IPB Forensic Scanner
//
//  Created by Bradley Snyder on 12/1/13.
//  Copyright (c) 2013 Bradley Snyder. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface FSFileUtils : NSObject

+ (NSString*)parseNextString:(NSFileHandle*)fileHandle;
+ (uint8_t)parseNextInt8:(NSFileHandle*)fileHandle;
+ (uint16_t)parseNextInt16:(NSFileHandle*)fileHandle;
+ (uint32_t)parseNextInt32:(NSFileHandle*)fileHandle;
+ (uint64_t)parseNextInt64:(NSFileHandle*)fileHandle;

@end
