//
//  FSSMSMessage.h
//  IPB Forensic Scanner
//
//  Created by Bradley Snyder on 2/20/14.
//  Copyright (c) 2014 Bradley Snyder. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface FSSMSMessage : NSObject

@property NSString *handle;
@property NSString *text;
@property NSString *guid;
@property NSString *service;
@property NSDate *date;
@property NSDate *dateRead;
@property BOOL isFromMe;
@property BOOL isSent;
@property BOOL isRead;

@end
