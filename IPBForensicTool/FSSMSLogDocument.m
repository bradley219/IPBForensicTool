//
//  FSSMSLogDocument.m
//  IPB Forensic Scanner
//
//  Created by Bradley Snyder on 2/20/14.
//  Copyright (c) 2014 Bradley Snyder. All rights reserved.
//

#import "FSSMSLogDocument.h"

@interface FSSMSLogDocument() {
    NSMutableAttributedString *_string;
    NSDateFormatter *_dateFormatter;
    
    NSFont *_headerFont;
    NSFont *_bigFont;
    NSFont *_smallFont;
    NSFont *_smallBoldFont;
    
    NSColor *_greyColor;
    NSColor *_darkGreyColor;

}

@end

@implementation FSSMSLogDocument

- (id)init
{
    self = [super init];
    if( self )
    {
        [self initialize];
    }
    return self;
}

- (void)initialize
{
    _string = [[NSMutableAttributedString alloc]init];
    
    _dateFormatter = [[NSDateFormatter alloc]init];
    _dateFormatter.dateFormat = @"MMM d, YYYY HH:mm:ss zzz";
    
    NSString *fontFamily = @"Helvetica";
    NSInteger headerSize = 14;
    NSInteger bigSize = 12;
    NSInteger smallSize = 8;
    NSFontManager *fontManager = [NSFontManager sharedFontManager];
    
    _headerFont = [fontManager fontWithFamily:fontFamily
                                       traits:NSBoldFontMask
                                       weight:0
                                         size:headerSize];
    
    _bigFont = [fontManager fontWithFamily:fontFamily
                                    traits:NSBoldFontMask
                                    weight:0
                                      size:bigSize];
    
    _smallFont = [fontManager fontWithFamily:fontFamily
                                      traits:0
                                      weight:0
                                        size:smallSize];
    _smallBoldFont = [fontManager fontWithFamily:fontFamily
                                          traits:0
                                          weight:1.5
                                            size:smallSize];
    
    CGFloat greyVal;
    greyVal = 0.5;
    _greyColor = [NSColor colorWithDeviceRed:greyVal green:greyVal blue:greyVal alpha:1.0];
    
    greyVal = 0.3;
    _darkGreyColor = [NSColor colorWithDeviceRed:greyVal green:greyVal blue:greyVal alpha:1.0];
}

- (NSData *)dataOfType:(NSString *)typeName error:(NSError **)outError
{
    NSDictionary *attributes = @{ NSDocumentTypeDocumentAttribute: NSRTFTextDocumentType };
    
    NSData *data = [_string RTFFromRange:NSMakeRange(0, _string.length) documentAttributes:attributes];
    return data;
}

- (NSAttributedString*)formattedStringForKey:(NSString*)key value:(NSString*)value withParagraphStyle:(NSParagraphStyle*)paragraphStyle
{
    NSMutableAttributedString *str = [[NSMutableAttributedString alloc]init];
    
    NSDictionary *keyAttributes = @{
                                 NSParagraphStyleAttributeName: paragraphStyle,
                                 NSFontAttributeName: _smallFont,
                                 NSForegroundColorAttributeName: _darkGreyColor,
                                 };
    NSDictionary *valAttributes = @{
                                    NSParagraphStyleAttributeName: paragraphStyle,
                                    NSFontAttributeName: _smallFont,
                                    NSForegroundColorAttributeName: _greyColor,
                                    };
    if( !key )
    {
        key = @"";
    }
    if( !value )
    {
        value = @"";
    }
    [str appendAttributedString:[[NSAttributedString alloc]initWithString:[key stringByAppendingString:@": "] attributes:keyAttributes]];
    [str appendAttributedString:[[NSAttributedString alloc]initWithString:[value stringByAppendingString:@"\n"] attributes:valAttributes]];
    
    return str;
}

- (void)addMessage:(FSSMSMessage *)message
{
    NSString *fromTo;
    NSString *recvSent;
    NSMutableParagraphStyle *paragraphStyle = [[NSMutableParagraphStyle alloc]init];
    
    if( message.isFromMe )
    {
        paragraphStyle.alignment = NSRightTextAlignment;
        fromTo = @"To";
        recvSent = @"Sent";
    }
    else
    {
        paragraphStyle.alignment = NSLeftTextAlignment;
        fromTo = @"From";
        recvSent = @"Received";
    }
    
    NSDictionary *attributes;
    
    // Big text
    attributes = @{
                   NSParagraphStyleAttributeName: paragraphStyle,
                   NSFontAttributeName: _bigFont,
                   NSForegroundColorAttributeName: [NSColor blackColor],
                   };
    if( !message.text )
    {
        message.text = @"";
    }
    [_string appendAttributedString:[[NSAttributedString alloc] initWithString:[message.text stringByAppendingString:@"\n"] attributes:attributes]];

    
    // SMS From: +13109999944
    [_string appendAttributedString:[self formattedStringForKey:[NSString stringWithFormat:@"%@ %@", message.service, fromTo]
                                                          value:message.handle
                                             withParagraphStyle:paragraphStyle]];
    
    // Received:
    [_string appendAttributedString:[self formattedStringForKey:recvSent
                                                          value:[_dateFormatter stringFromDate:message.date]
                                             withParagraphStyle:paragraphStyle]];
    
    if( message.isRead && message.dateRead )
    {
        // Read:
        [_string appendAttributedString:[self formattedStringForKey:@"Read"
                                                              value:[_dateFormatter stringFromDate:message.dateRead]
                                                 withParagraphStyle:paragraphStyle]];
    }
    
    [_string appendAttributedString:[[NSAttributedString alloc]initWithString:@"\n" attributes:attributes]];
    
}

- (void)addHeader:(NSString *)header
{
    NSMutableParagraphStyle *paragraphStyle = [[NSMutableParagraphStyle alloc]init];
    paragraphStyle.alignment = NSCenterTextAlignment;
    
    NSDictionary *attributes = @{
                                 NSParagraphStyleAttributeName: paragraphStyle,
                                 NSFontAttributeName: _headerFont,
                                 NSForegroundColorAttributeName: [NSColor blackColor],
                                 };

    if( !header )
    {
        header = @"";
    }
    
    [_string appendAttributedString:[[NSAttributedString alloc]initWithString:[header stringByAppendingString:@"\n\n"] attributes:attributes]];
}

@end
