//
//  FSAppDelegate.m
//  IPB Forensic Scanner
//
//  Created by Bradley Snyder on 11/30/13.
//  Copyright (c) 2013 ___FULLUSERNAME___. All rights reserved.
//

#import "FSAppDelegate.h"
#import <FMDatabase.h>

@implementation FSAppDelegate

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification
{
    // Insert code here to initialize your application
    
    NSLog(@"applicationDidFinishLaunching");
    NSLog(@"sqlite library version %@", [FMDatabase sqliteLibVersion]);
}

- (BOOL)application:(NSApplication *)sender openFile:(NSString *)filename
{
    return NO;
}

@end
