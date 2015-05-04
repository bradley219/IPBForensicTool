//
//  FSSMSLogDocument.h
//  IPB Forensic Scanner
//
//  Created by Bradley Snyder on 2/20/14.
//  Copyright (c) 2014 Bradley Snyder. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import "FSSMSMessage.h"

@interface FSSMSLogDocument : NSDocument

- (void)addMessage:(FSSMSMessage*)message;
- (void)addHeader:(NSString*)header;

@end
