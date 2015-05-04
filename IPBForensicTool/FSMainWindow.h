//
//  FSMainWindow.h
//  IPB Forensic Scanner
//
//  Created by Bradley Snyder on 11/30/13.
//  Copyright (c) 2013 Bradley Snyder. All rights reserved.
//

#import <Cocoa/Cocoa.h>

@interface FSMainWindow : NSWindow <NSWindowDelegate>

- (IBAction)extractButtonAction:(id)sender;
@property IBOutlet NSButton *extractButton;
@property IBOutlet NSPopUpButton *targetPopup;
@property IBOutlet NSPopUpButton *handlePopup;
- (IBAction)openButtonAction:(id)sender;
- (IBAction)handlePopupAction:(id)sender;


@end
