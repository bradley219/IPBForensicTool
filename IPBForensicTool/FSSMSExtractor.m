//
//  FSSMSExtractor.m
//  IPB Forensic Scanner
//
//  Created by Bradley Snyder on 2/20/14.
//  Copyright (c) 2014 Bradley Snyder. All rights reserved.
//

#import "FSSMSExtractor.h"
#import <FMDatabase.h>
#import "FSSMSMessage.h"
#import "FSSMSLogDocument.h"


@interface FSSMSExtractor() {
    FSManifestDB *_manifest;
    FSManifestDBRecord *_record;
    NSURL *_dbPath;
    
    FMDatabase *_db;
}

@end

@implementation FSSMSExtractor

- (id)initWithManifest:(FSManifestDB *)manifest
{
    self = [super init];
    if( self )
    {
        _manifest = manifest;
        [self initialize];
    }
    return self;
}

- (void)initialize
{
    _dbPath = nil;
    _record = [_manifest searchRecordWithDomain:@"HomeDomain" path:@"Library/SMS/sms.db"];
}

- (void)dealloc
{
    [self closeDB];
    if( _dbPath && [_dbPath checkResourceIsReachableAndReturnError:nil] )
    {
        [[NSFileManager defaultManager]removeItemAtURL:_dbPath error:nil];
    }
}

- (BOOL)parse
{
    BOOL success = NO;
    
    if( _record )
    {
        NSString *tempDirPath = @"/tmp/";
        NSURL *path = [NSURL fileURLWithPath:[tempDirPath stringByAppendingString:@"sms.db"]];
        if( [path checkResourceIsReachableAndReturnError:nil] )
        {
            [[NSFileManager defaultManager]removeItemAtURL:path error:nil];
        }
        
        BOOL s = [_record copyFileToExactPath:path];
        if( s )
        {
            _dbPath = path;
            
            success = [self openDB];
            if( success )
            {
                [self getHandles];
            }
        }
    }
    
    return success;
}

- (BOOL)openDB
{
    _db = [FMDatabase databaseWithPath:_dbPath.path];
    [_db openWithFlags:SQLITE_OPEN_READONLY];
    return [_db goodConnection];
}

- (void)closeDB
{
    [_db close];
}

- (BOOL)getHandles
{
    BOOL success = NO;
    
    NSString *handleQuery = @"SELECT 'handle'.'id' FROM 'handle' GROUP BY 'handle'.'id' ORDER BY 'handle'.'id'";
    FMResultSet *handles = [_db executeQuery:handleQuery];
    
    if( handles )
    {
        NSMutableArray *ids = [[NSMutableArray alloc]init];
        
        while( [handles next] )
        {
            NSString *idStr = [handles stringForColumnIndex:0];
            [ids addObject:idStr];
        }
        
        _handleIDs = ids;
        success = YES;
    }
    else
    {
        NSLog(@"Error: %@", [_db lastErrorMessage]);
    }
    
    return success;
}

- (BOOL)extractForHandleID:(NSString *)handleID
{
    BOOL success = NO;
    
    FSSMSLogDocument *document = [[FSSMSLogDocument alloc]init];
    
    FMResultSet *chats = [_db executeQuery:@"SELECT 'chat'.* FROM 'chat' INNER JOIN 'chat_handle_join' ON( 'chat_handle_join'.'chat_id' = 'chat'.'ROWID' ) INNER JOIN 'handle' ON( 'chat_handle_join'.'handle_id' = 'handle'.'ROWID' ) WHERE 'handle'.'id' = ? ORDER BY 'chat'.'ROWID'", handleID];
    
    if( chats )
    {
        while( [chats next] )
        {
            NSNumber *chatID = [NSNumber numberWithInteger:[[chats stringForColumn:@"ROWID"]integerValue]];
            
            // Create chat header
            FMResultSet *handles = [_db executeQuery:@"SELECT 'handle'.'id' FROM 'chat_handle_join' INNER JOIN 'chat' ON( 'chat_handle_join'.'chat_id' = 'chat'.'ROWID' ) INNER JOIN 'handle' ON( 'chat_handle_join'.'handle_id' = 'handle'.'ROWID' ) WHERE 'chat_handle_join'.'chat_id' = ? ORDER BY 'chat_handle_join'.'chat_id'", chatID];
            NSMutableArray *handleStrings = [[NSMutableArray alloc]init];
            if( handles )
            {
                while( [handles next] )
                {
                    [handleStrings addObject:[handles stringForColumn:@"id"]];
                }
            }
            NSString *chatHeader = [NSString stringWithFormat:@"Chat with: %@",[handleStrings componentsJoinedByString:@", "]];
            [document addHeader:chatHeader];
            
            // Gather messages
            FMResultSet *messages = [_db executeQuery:@"SELECT * FROM 'message' INNER JOIN 'chat_message_join' ON( 'message'.'ROWID' = 'chat_message_join'.'message_id' ) INNER JOIN 'chat' ON( 'chat'.'ROWID' = 'chat_message_join'.'chat_id' ) LEFT JOIN handle ON( message.handle_id = handle.ROWID ) WHERE chat_id = ? ORDER BY 'message'.'date', 'message'.'ROWID'", chatID];
            
            if( messages )
            {
                while( [messages next] )
                {
                    FSSMSMessage *msg = [[FSSMSMessage alloc]init];
                    
                    msg.handle = [messages stringForColumn:@"id"];
                    if( !msg.handle )
                    {
                        msg.handle = [handleStrings componentsJoinedByString:@", "];
                    }
                    
                    msg.isFromMe = [messages boolForColumn:@"is_from_me"];
                    msg.isSent = [messages boolForColumn:@"is_sent"];
                    msg.isRead = [messages boolForColumn:@"is_read"];
                    
                    if( !msg.isFromMe || msg.isRead )
                    {
                        msg.dateRead = [NSDate dateWithTimeIntervalSinceReferenceDate:[messages doubleForColumn:@"date_read"]];
                    }
                    else
                    {
                        msg.dateRead = nil;
                    }
                    
                    msg.date = [NSDate dateWithTimeIntervalSinceReferenceDate:[messages doubleForColumn:@"date"]];
                    msg.text = [messages stringForColumn:@"text"];
                    msg.guid = [messages stringForColumn:@"guid"];
                    msg.service = [messages stringForColumn:@"service"];
                    if( !msg.service )
                    {
                        msg.service = [messages stringForColumn:@"service_name"];
                    }
                    
                    [document addMessage:msg];
                }
            }
        }
    }
    
    NSSavePanel *savePanel = [NSSavePanel savePanel];
    savePanel.canCreateDirectories = YES;
    [savePanel setExtensionHidden:NO];
    [savePanel setAllowedFileTypes:[NSArray arrayWithObject:@"rtf"]];
    savePanel.nameFieldStringValue = [NSString stringWithFormat:@"%@ Message Log", handleID];
    
    [savePanel beginWithCompletionHandler:^(NSInteger result){
        if( result == NSFileHandlingPanelOKButton )
        {
            
            NSError *error = nil;
            [document saveToURL:savePanel.URL ofType:NSRTFTextDocumentType forSaveOperation:NSSaveAsOperation error:&error];
            if( error )
            {
                NSLog(@"save error: %@", error);
            }
        }
    }];
    
    return success;
}

@end
