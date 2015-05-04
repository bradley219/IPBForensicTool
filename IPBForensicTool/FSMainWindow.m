//
//  FSMainWindow.m
//  IPB Forensic Scanner
//
//  Created by Bradley Snyder on 11/30/13.
//  Copyright (c) 2013 Bradley Snyder. All rights reserved.
//

#import "FSMainWindow.h"
#import "FSBackupPackage.h"
#import "FSSMSExtractor.h"


@interface FSMainWindow() {
    BOOL _targetsInited;
    NSArray *_packages;
    FSSMSExtractor *_extractor;
}

@property FSBackupPackage *backupPackage;

@end

@implementation FSMainWindow

- (id)initWithCoder:(NSCoder *)aDecoder
{
    self = [super initWithCoder:aDecoder];
    [self initialize];
    return self;
}

- (id)initWithContentRect:(NSRect)contentRect styleMask:(NSUInteger)aStyle backing:(NSBackingStoreType)bufferingType defer:(BOOL)flag
{
    self = [super initWithContentRect:contentRect styleMask:aStyle backing:bufferingType defer:flag];
    [self initialize];
    return self;
}

- (id)initWithContentRect:(NSRect)contentRect styleMask:(NSUInteger)aStyle backing:(NSBackingStoreType)bufferingType defer:(BOOL)flag screen:(NSScreen *)screen
{
    self = [super initWithContentRect:contentRect styleMask:aStyle backing:bufferingType defer:flag screen:screen];
    [self initialize];
    return self;
}

- (void)initialize
{
    _targetsInited = NO;
    self.delegate = self;
    _backupPackage = nil;
    [self.extractButton setEnabled:NO];
    
}

- (void)windowDidBecomeKey:(NSNotification *)notification
{
    NSLog(@"windowDidBecomeKey");
    [self initTargets];
}

- (void)initTargets
{
    NSLog(@"initTargets start");
    if( _targetsInited )
    {
        return;
    }
    
    NSMutableArray *packages = [[NSMutableArray alloc]init];
    
    [self.targetPopup removeAllItems];
    
    NSError *e = nil;
    NSString *dirpath = [NSHomeDirectory() stringByAppendingString:@"/Library/Application Support/MobileSync/Backup"];
    NSArray *contents = [[NSFileManager defaultManager]contentsOfDirectoryAtPath:dirpath error:&e];
    
    NSDateFormatter *dateFormatter = [[NSDateFormatter alloc]init];
    dateFormatter.dateFormat = @"MMM d, YYYY HH:mm:ss zzz";
    
    if( contents )
    {
        for( NSString *name in contents )
        {
            NSString *fullPath = [NSString stringWithFormat:@"%@/%@", dirpath, name];
            NSURL *url = [[NSURL alloc]initFileURLWithPath:fullPath];
            FSBackupPackage *pkg = [FSBackupPackage backupPackageWithBaseURL:url];
            if( [pkg scan] )
            {
                NSString *title = [NSString stringWithFormat:@"%@ (%@)", pkg.deviceName, [dateFormatter stringFromDate:pkg.backupDate]];
                [self.targetPopup addItemWithTitle:title];
                [packages addObject:pkg];
            }
        }
    }
    
    _packages = packages;
    _targetsInited = YES;
    NSLog(@"initTargets finish");
}

- (IBAction)openButtonAction:(id)sender
{
    NSInteger index = [self.targetPopup indexOfSelectedItem];
    
    if( _packages.count >= index + 1 )
    {
        FSBackupPackage *pkg = [_packages objectAtIndex:index];
        FSManifestDB *manifest = pkg.manifestDB;
        
        _extractor = [[FSSMSExtractor alloc]initWithManifest:manifest];
        if( [_extractor parse] )
        {
            NSArray *handles = _extractor.handleIDs;
            [self.handlePopup removeAllItems];
            for( NSString *handleID in handles )
            {
                [self.handlePopup addItemWithTitle:handleID];
            }
            [self.handlePopup setHidden:NO];
            [self.extractButton setEnabled:YES];
        }
        else
        {
            // TODO: error message
            [self.extractButton setEnabled:NO];
        }
    }
}


- (IBAction)extractButtonAction:(id)sender
{
    NSString *handleID = [self.handlePopup titleOfSelectedItem];
    [_extractor extractForHandleID:handleID];
}


- (IBAction)handlePopupAction:(id)sender
{
    NSPopUpButton *popup = sender;
    [popup sizeToFit];
}


@end
