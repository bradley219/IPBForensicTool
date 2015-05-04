//
//  FSUtils.h
//  IPB Forensic Scanner
//
//  Created by Bradley Snyder on 12/1/13.
//  Copyright (c) 2013 Bradley Snyder. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface FSUtils : NSObject

+ (NSString*)hexStringFromData:(NSData*)data;
+ (NSString*)sha1Digest:(NSString*)string;

@end
