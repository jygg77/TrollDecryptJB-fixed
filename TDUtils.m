#import "TDUtils.h"
#import "TDDumpDecrypted.h"
#import "LSApplicationProxy+AltList.h"
#import "SSZipArchive/SSZipArchive.h"
#import "appstoretrollerKiller/TSUtil.h"
#include <sys/stat.h>
#include <spawn.h>

extern char **environ;

#define POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE 1
extern int posix_spawnattr_set_persona_np(const posix_spawnattr_t* __restrict, uid_t, uint32_t);
extern int posix_spawnattr_set_persona_uid_np(const posix_spawnattr_t* __restrict, uid_t);
extern int posix_spawnattr_set_persona_gid_np(const posix_spawnattr_t* __restrict, uid_t);

#if __has_include(<roothide.h>)
#import <roothide.h>
#define JB_ROOT_PATH_NS(path) jbroot(path)
#elif __has_include(<rootless.h>)
#import <rootless.h>
#define JB_ROOT_PATH_NS(path) ROOT_PATH_NS(path)
#else
#define JB_ROOT_PATH_NS(path) path
#endif

#ifndef ROOT_PATH_NS
#define ROOT_PATH_NS(path) JB_ROOT_PATH_NS(path)
#endif

static NSString *resolveToolPath(NSString *name, NSString *fallbackPath) {
    NSFileManager *fm = [NSFileManager defaultManager];
    // Check main bundle first
    NSString *bundlePath = [[NSBundle mainBundle] pathForResource:name ofType:nil];
    if (bundlePath && [fm fileExistsAtPath:bundlePath]) {
        return bundlePath;
    }
    // Check roothide / rootless dynamic path
    NSString *jbPath = JB_ROOT_PATH_NS(fallbackPath);
    if (jbPath && [fm fileExistsAtPath:jbPath]) {
        return jbPath;
    }
    // Also check standard /var/jb
    NSString *varJbPath = [@"/var/jb" stringByAppendingPathComponent:fallbackPath];
    if ([fm fileExistsAtPath:varJbPath]) {
        return varJbPath;
    }
    // Check raw fallback path
    if ([fm fileExistsAtPath:fallbackPath]) {
        return fallbackPath;
    }
    return nil;
}

#include <mach-o/fat.h>
#include <libkern/OSByteOrder.h>

NSString *sanitizeFilename(NSString *input) {
    if (!input || input.length == 0) return @"unnamed";
    NSCharacterSet *invalidChars = [NSCharacterSet characterSetWithCharactersInString:@"/\\?%*:\0|<>\"'\r\n\t"];
    NSString *clean = [[input componentsSeparatedByCharactersInSet:invalidChars] componentsJoinedByString:@"_"];
    clean = [clean stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    return clean.length > 0 ? clean : @"unnamed";
}

static NSString *createSecureTempDir(NSString *prefix) {
    NSString *base = NSTemporaryDirectory() ?: @"/tmp";
    NSString *cleanPrefix = sanitizeFilename(prefix);
    NSString *templatePath = [base stringByAppendingPathComponent:[NSString stringWithFormat:@"%@_XXXXXX", cleanPrefix]];
    char *templateCString = strdup([templatePath fileSystemRepresentation]);
    if (!templateCString) return nil;
    char *dirPath = mkdtemp(templateCString);
    if (!dirPath) {
        free(templateCString);
        return nil;
    }
    NSString *result = [NSString stringWithUTF8String:dirPath];
    free(templateCString);
    return result;
}

BOOL isMachOEncrypted(NSString *filePath) {
    if (!filePath || filePath.length == 0) return NO;
    
    int fd = open([filePath fileSystemRepresentation], O_RDONLY);
    if (fd < 0) return NO;
    
    uint32_t magic = 0;
    if (read(fd, &magic, sizeof(magic)) != sizeof(magic)) {
        close(fd);
        return NO;
    }
    
    BOOL (^checkSlice)(off_t offset) = ^BOOL(off_t offset) {
        if (lseek(fd, offset, SEEK_SET) < 0) return NO;
        
        uint32_t sliceMagic = 0;
        if (read(fd, &sliceMagic, sizeof(sliceMagic)) != sizeof(sliceMagic)) return NO;
        
        BOOL is64 = (sliceMagic == MH_MAGIC_64 || sliceMagic == MH_CIGAM_64);
        BOOL is32 = (sliceMagic == MH_MAGIC || sliceMagic == MH_CIGAM);
        if (!is64 && !is32) return NO;
        
        BOOL needSwap = (sliceMagic == MH_CIGAM || sliceMagic == MH_CIGAM_64);
        uint32_t ncmds = 0;
        uint32_t sizeofcmds = 0;
        
        if (is64) {
            struct mach_header_64 header;
            if (lseek(fd, offset, SEEK_SET) < 0) return NO;
            if (read(fd, &header, sizeof(header)) != sizeof(header)) return NO;
            ncmds = needSwap ? OSSwapInt32(header.ncmds) : header.ncmds;
            sizeofcmds = needSwap ? OSSwapInt32(header.sizeofcmds) : header.sizeofcmds;
        } else {
            struct mach_header header;
            if (lseek(fd, offset, SEEK_SET) < 0) return NO;
            if (read(fd, &header, sizeof(header)) != sizeof(header)) return NO;
            ncmds = needSwap ? OSSwapInt32(header.ncmds) : header.ncmds;
            sizeofcmds = needSwap ? OSSwapInt32(header.sizeofcmds) : header.sizeofcmds;
        }
        
        if (sizeofcmds == 0 || ncmds == 0 || sizeofcmds > 2 * 1024 * 1024) return NO;
        
        void *cmdBuf = malloc(sizeofcmds);
        if (!cmdBuf) return NO;
        
        if (read(fd, cmdBuf, sizeofcmds) != sizeofcmds) {
            free(cmdBuf);
            return NO;
        }
        
        BOOL encrypted = NO;
        uint8_t *cur = (uint8_t *)cmdBuf;
        uint8_t *end = cur + sizeofcmds;
        
        for (uint32_t i = 0; i < ncmds && cur + sizeof(struct load_command) <= end; i++) {
            struct load_command *lc = (struct load_command *)cur;
            uint32_t cmd = needSwap ? OSSwapInt32(lc->cmd) : lc->cmd;
            uint32_t cmdsize = needSwap ? OSSwapInt32(lc->cmdsize) : lc->cmdsize;
            
            if (cmdsize < sizeof(struct load_command) || cur + cmdsize > end) break;
            
            if (cmd == LC_ENCRYPTION_INFO) {
                struct encryption_info_command *enc = (struct encryption_info_command *)cur;
                uint32_t cryptid = needSwap ? OSSwapInt32(enc->cryptid) : enc->cryptid;
                if (cryptid > 0) {
                    encrypted = YES;
                    break;
                }
            } else if (cmd == LC_ENCRYPTION_INFO_64) {
                struct encryption_info_command_64 *enc = (struct encryption_info_command_64 *)cur;
                uint32_t cryptid = needSwap ? OSSwapInt32(enc->cryptid) : enc->cryptid;
                if (cryptid > 0) {
                    encrypted = YES;
                    break;
                }
            }
            cur += cmdsize;
        }
        
        free(cmdBuf);
        return encrypted;
    };
    
    BOOL isEncrypted = NO;
    
    if (magic == FAT_MAGIC || magic == FAT_CIGAM) {
        BOOL needSwap = (magic == FAT_CIGAM);
        struct fat_header fhdr;
        lseek(fd, 0, SEEK_SET);
        if (read(fd, &fhdr, sizeof(fhdr)) == sizeof(fhdr)) {
            uint32_t nfat_arch = needSwap ? OSSwapInt32(fhdr.nfat_arch) : fhdr.nfat_arch;
            for (uint32_t i = 0; i < nfat_arch && i < 16; i++) {
                struct fat_arch arch;
                if (read(fd, &arch, sizeof(arch)) != sizeof(arch)) break;
                off_t offset = needSwap ? OSSwapInt32(arch.offset) : arch.offset;
                off_t currentPos = lseek(fd, 0, SEEK_CUR);
                if (checkSlice(offset)) {
                    isEncrypted = YES;
                    break;
                }
                lseek(fd, currentPos, SEEK_SET);
            }
        }
    } else if (magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64) {
        BOOL needSwap = (magic == FAT_CIGAM_64);
        struct fat_header fhdr;
        lseek(fd, 0, SEEK_SET);
        if (read(fd, &fhdr, sizeof(fhdr)) == sizeof(fhdr)) {
            uint32_t nfat_arch = needSwap ? OSSwapInt32(fhdr.nfat_arch) : fhdr.nfat_arch;
            for (uint32_t i = 0; i < nfat_arch && i < 16; i++) {
                struct fat_arch_64 arch;
                if (read(fd, &arch, sizeof(arch)) != sizeof(arch)) break;
                off_t offset = needSwap ? OSSwapInt64(arch.offset) : arch.offset;
                off_t currentPos = lseek(fd, 0, SEEK_CUR);
                if (checkSlice(offset)) {
                    isEncrypted = YES;
                    break;
                }
                lseek(fd, currentPos, SEEK_SET);
            }
        }
    } else {
        isEncrypted = checkSlice(0);
    }
    
    close(fd);
    return isEncrypted;
}

UIWindow *alertWindow = NULL;
UIWindow *kw = NULL;
UIViewController *root = NULL;
UIAlertController *alertController = NULL;
UIAlertController *doneController = NULL;
UIAlertController *errorController = NULL;

static void dismissAndCleanup(UIAlertController *alertToDismiss, void (^completion)(void)) {
    if (alertToDismiss && alertToDismiss.presentingViewController) {
        [alertToDismiss dismissViewControllerAnimated:YES completion:^{
            if (completion) completion();
        }];
    } else {
        if (completion) completion();
    }
}

static NSString *g_lastDecryptionError = nil;

static void showResultAlert(NSString *title, NSString *message, NSString *filePath, BOOL success) {
    dispatch_async(dispatch_get_main_queue(), ^{
        dismissAndCleanup(alertController, ^{
            UIAlertController *alert = [UIAlertController alertControllerWithTitle:title
                message:message
                preferredStyle:UIAlertControllerStyleAlert];

            UIAlertAction *okAction = [UIAlertAction actionWithTitle:@"Ok" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
                if (kw) {
                    [kw removeFromSuperview];
                    kw.hidden = YES;
                    kw = nil;
                    alertWindow = nil;
                }
            }];
            [alert addAction:okAction];

            if (success && filePath && [[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:@"filza://"]]) {
                UIAlertAction *openAction = [UIAlertAction actionWithTitle:@"Open in Filza" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
                    if (kw) {
                        [kw removeFromSuperview];
                        kw.hidden = YES;
                        kw = nil;
                        alertWindow = nil;
                    }
                    NSString *urlString = [NSString stringWithFormat:@"filza://view%@", filePath];
                    [[UIApplication sharedApplication] openURL:[NSURL URLWithString:urlString] options:@{} completionHandler:nil];
                }];
                [alert addAction:openAction];
            }

            [root presentViewController:alert animated:YES completion:nil];
        });
    });
}

NSArray *appList(void) {
    NSMutableArray *apps = [NSMutableArray array];

    NSArray <LSApplicationProxy *> *installedApplications = [[LSApplicationWorkspace defaultWorkspace] atl_allInstalledApplications];
    [installedApplications enumerateObjectsUsingBlock:^(LSApplicationProxy *proxy, NSUInteger idx, BOOL *stop) {
        if (![proxy atl_isUserApplication]) return;

        NSString *bundleID = [proxy atl_bundleIdentifier];
        NSString *name = [proxy atl_nameToDisplay];
        NSString *version = [proxy atl_shortVersionString];
        NSString *executable = proxy.canonicalExecutablePath;

        if (!bundleID || !name || !version || !executable) return;

        NSDictionary *item = @{
            @"bundleID":bundleID,
            @"name":name,
            @"version":version,
            @"executable":executable
        };

        [apps addObject:item];
    }];

    NSSortDescriptor *descriptor = [[NSSortDescriptor alloc] initWithKey:@"name" ascending:YES selector:@selector(localizedCaseInsensitiveCompare:)];
    [apps sortUsingDescriptors:@[descriptor]];

    [apps addObject:@{@"bundleID":@"", @"name":@"", @"version":@"", @"executable":@""}];

    return [apps copy];
}

NSUInteger iconFormat(void) {
    return (UIDevice.currentDevice.userInterfaceIdiom == UIUserInterfaceIdiomPad) ? 8 : 10;
}

NSArray *sysctl_ps(void) {
    NSMutableArray *array = [[NSMutableArray alloc] init];

    int numberOfProcesses = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0);
    pid_t pids[numberOfProcesses];
    bzero(pids, sizeof(pids));
    proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pids));
    for (int i = 0; i < numberOfProcesses; ++i) {
        if (pids[i] == 0) { continue; }
        char pathBuffer[PROC_PIDPATHINFO_MAXSIZE];
        bzero(pathBuffer, PROC_PIDPATHINFO_MAXSIZE);
        proc_pidpath(pids[i], pathBuffer, sizeof(pathBuffer));

        if (strlen(pathBuffer) > 0) {
            NSString *processID = [[NSString alloc] initWithFormat:@"%d", pids[i]];
            NSString *processName = [[NSString stringWithUTF8String:pathBuffer] lastPathComponent];
            NSDictionary *dict = [[NSDictionary alloc] initWithObjects:[NSArray arrayWithObjects:processID, processName, nil] forKeys:[NSArray arrayWithObjects:@"pid", @"proc_name", nil]];
            
            [array addObject:dict];
        }
    }

    return [array copy];
}

static NSString *getLogPath(void) {
    return @"/tmp/lldb_output.log";
}

static BOOL waitForContentOfFileSync(NSString *filePath, NSString *content, NSTimeInterval timeout) {
    NSTimeInterval startTime = [NSDate timeIntervalSinceReferenceDate];
    while ([NSDate timeIntervalSinceReferenceDate] - startTime < timeout) {
        @autoreleasepool {
            if ([[NSFileManager defaultManager] fileExistsAtPath:filePath]) {
                NSString *fileContent = [NSString stringWithContentsOfFile:filePath encoding:NSUTF8StringEncoding error:nil];
                if (fileContent && [fileContent containsString:content]) {
                    NSLog(@"[trolldecrypt] File content matched: %@", filePath);
                    return YES;
                }
            }
        }
        usleep(100000); // 100ms
    }
    return NO;
}

static NSString *lldbQuotedProcessName(const char *executableName) {
    if (!executableName) {
        return nil;
    }
    NSString *name = [NSString stringWithUTF8String:executableName];
    if (!name) {
        return nil;
    }

    NSCharacterSet *controlSet = [NSCharacterSet controlCharacterSet];
    NSMutableString *sanitized = [NSMutableString stringWithCapacity:name.length];
    for (NSUInteger i = 0; i < name.length; i++) {
        unichar c = [name characterAtIndex:i];
        if ([controlSet characterIsMember:c]) {
            continue;
        }
        [sanitized appendFormat:@"%C", c];
    }

    NSString *escaped = [[sanitized stringByReplacingOccurrencesOfString:@"\\" withString:@"\\\\"]
                         stringByReplacingOccurrencesOfString:@"\"" withString:@"\\\""];
    return [NSString stringWithFormat:@"\"%@\"", escaped];
}

static NSString *getLLDBPath(void) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *p = JB_ROOT_PATH_NS(@"/usr/bin/lldb");
    if (p && [fm fileExistsAtPath:p]) return p;
    if ([fm fileExistsAtPath:@"/var/jb/usr/bin/lldb"]) return @"/var/jb/usr/bin/lldb";
    if ([fm fileExistsAtPath:@"/usr/bin/lldb"]) return @"/usr/bin/lldb";
    return nil;
}

pid_t attachLLDBToProcessByName(const char *executableName, pid_t target_pid) {
    setuid(0);
    seteuid(0);
    NSLog(@"[trolldecrypt] Attaching lldb to executable: %s (PID: %d)", executableName, target_pid);
    NSString *quotedName = lldbQuotedProcessName(executableName);
    if (!quotedName) {
        NSLog(@"[trolldecrypt] Invalid executable name for lldb attach");
        return 0;
    }
    NSString *logPath = getLogPath();
    [[NSFileManager defaultManager] removeItemAtPath:logPath error:nil];

    pid_t lldb_pid = 0;
    NSString *lldbPathNS = getLLDBPath();
    if (!lldbPathNS) {
        NSLog(@"[trolldecrypt] lldb binary not found!");
        return 0;
    }
    const char *lldb_path = [lldbPathNS UTF8String];
    NSString *oneLineCmd = [NSString stringWithFormat:@"process attach --name %@ --waitfor", quotedName];
    const char *args[] = {
        "lldb",
        "--batch",
        "-o", [oneLineCmd UTF8String],
        NULL
    };
    
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    int persona_id = available_persona_id();
    if (persona_id > 0) {
        posix_spawnattr_set_persona_np(&attr, persona_id, POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE);
        posix_spawnattr_set_persona_uid_np(&attr, 0);
        posix_spawnattr_set_persona_gid_np(&attr, 0);
    }
    
    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);

    posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO, [logPath UTF8String], O_WRONLY | O_CREAT | O_TRUNC, 0666);
    posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, [logPath UTF8String], O_WRONLY | O_CREAT | O_APPEND, 0666);
    
    int status = posix_spawn(&lldb_pid, lldb_path, &actions, &attr, (char *const *)args, environ);
    posix_spawn_file_actions_destroy(&actions);
    posix_spawnattr_destroy(&attr);
    
    if (status == 0) {
        NSLog(@"[trolldecrypt] lldb spawned done, lldb PID: %d", lldb_pid);
        NSLog(@"[trolldecrypt] lldb output: %@", logPath);
        
        // Check if LLDB is alive; if not, read the output log
        usleep(300000); // 300ms
        if (kill(lldb_pid, 0) != 0) {
            NSString *outLog = [NSString stringWithContentsOfFile:logPath encoding:NSUTF8StringEncoding error:nil];
            NSLog(@"[trolldecrypt] lldb process died prematurely. Log: %@", outLog);
            g_lastDecryptionError = [NSString stringWithFormat:@"LLDB exited immediately.\nOutput:\n%@", outLog ?: @"(no output)"];
            lldb_pid = 0;
        } else {
            NSLog(@"[trolldecrypt] lldb running and waiting for '%s' (PID: %d)", executableName, target_pid);
        }
    } else {
        NSLog(@"[trolldecrypt] fail to spawn lldb: %d", status);
        g_lastDecryptionError = [NSString stringWithFormat:@"posix_spawn failed with error: %d (%s)\nPath: %@", status, strerror(status), lldbPathNS];
        lldb_pid = 0;
    }
    
    return lldb_pid;
}

void detachLLDB(pid_t lldb_pid) {
    if (lldb_pid > 0) {
        NSLog(@"[trolldecrypt] Detaching lldb (PID: %d)", lldb_pid);

        kill(lldb_pid, SIGTERM);
        usleep(500000);
      
        if (kill(lldb_pid, 0) == 0) {
            NSLog(@"[trolldecrypt] lldb still running, sending SIGKILL");
            kill(lldb_pid, SIGKILL);
        }
        
        NSLog(@"[trolldecrypt] lldb detached successfully");

        int unused;
        waitpid(lldb_pid, &unused, WNOHANG);
    }
}

void bfinject_rocknroll(pid_t pid, NSString *appName, NSString *version, pid_t lldb_pid) {
    NSLog(@"[trolldecrypt] decrypt...");
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSLog(@"[trolldecrypt] Process PID: %d, lldb PID: %d", pid, lldb_pid);

        char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
        proc_pidpath(pid, pathbuf, sizeof(pathbuf));
        const char *fullPathStr = pathbuf;

        NSLog(@"[trolldecrypt] fullPathStr: %s", fullPathStr);
        NSLog(@"[trolldecrypt] Process is already PAUSED by lldb");
        
        DumpDecrypted *dd = [[DumpDecrypted alloc] initWithPathToBinary:[NSString stringWithUTF8String:fullPathStr] appName:appName appVersion:version];
        if(!dd) {
            NSLog(@"[trolldecrypt] ERROR: failed to get DumpDecrypted instance");
            detachLLDB(lldb_pid);
            kill(pid, SIGKILL);
            showResultAlert(@"Error", @"Failed to initialize DumpDecrypted engine.", nil, NO);
            return;
        }

        NSLog(@"[trolldecrypt] Full path to app: %s   ///   IPA File: %@", fullPathStr, [dd IPAPath]);

        NSLog(@"[trolldecrypt] Starting decryption while process is paused...");
        [dd createIPAFile:pid];
        NSLog(@"[trolldecrypt] Decryption complete!");

        NSLog(@"[trolldecrypt] Detaching lldb...");
        detachLLDB(lldb_pid);
        
        // Terminate target app
        kill(pid, SIGKILL);

        NSString *ipaFile = [dd IPAPath];
        if ([[NSFileManager defaultManager] fileExistsAtPath:ipaFile]) {
            showResultAlert(@"Decryption Complete!", [NSString stringWithFormat:@"IPA file saved to:\n%@\n\nSuccessfully decrypted using LLDB & SpringBoard suspended launch!", ipaFile], ipaFile, YES);
        } else {
            showResultAlert(@"Decryption Failed", @"IPA file was not generated or dump failed.", nil, NO);
        }
    });
}

void decryptAppWithLLDB(NSDictionary *app) {
    NSString *bundleID = app[@"bundleID"];
    NSString *name = app[@"name"];
    NSString *version = app[@"version"];
    NSString *executable = app[@"executable"];
    NSString *binaryName = [executable lastPathComponent];

    // Check if lldb is installed
    NSString *lldbPath = getLLDBPath();
    if (!lldbPath) {
        showResultAlert(@"LLDB Not Installed",
                        @"LLDB is required to decrypt apps that require higher iOS versions (e.g. iOS 17 apps on iOS 16).\n\nPlease install the 'lldb' package from Sileo or Zebra (Procursus repo).",
                        nil, NO);
        return;
    }

    dispatch_async(dispatch_get_main_queue(), ^{
        alertWindow = [[UIWindow alloc] initWithFrame: [UIScreen mainScreen].bounds];
        alertWindow.rootViewController = [UIViewController new];
        alertWindow.windowLevel = UIWindowLevelAlert + 1;
        [alertWindow makeKeyAndVisible];
        
        kw = alertWindow;
        if([kw respondsToSelector:@selector(topmostPresentedViewController)])
            root = [kw performSelector:@selector(topmostPresentedViewController)];
        else
            root = [kw rootViewController];
        root.modalPresentationStyle = UIModalPresentationFullScreen;

        alertController = [UIAlertController alertControllerWithTitle:@"Decrypting with LLDB"
                                                              message:@"Attaching debugger to suspended process...\nPlease wait a few moments."
                                                       preferredStyle:UIAlertControllerStyleAlert];
        [root presentViewController:alertController animated:YES completion:nil];
    });

    NSLog(@"[trolldecrypt] decrypt with LLDB: %@", name);

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSLog(@"[trolldecrypt] bundleID: %@", bundleID);
        NSLog(@"[trolldecrypt] name: %@", name);
        NSLog(@"[trolldecrypt] version: %@", version);
        NSLog(@"[trolldecrypt] executable: %@", executable);
        NSLog(@"[trolldecrypt] binaryName: %@", binaryName);

        // Kill existing process if any
        NSLog(@"[trolldecrypt] kill existing process if any...");
        NSArray *processes = sysctl_ps();
        for (NSDictionary *process in processes) {
            NSString *proc_name = process[@"proc_name"];
            if ([proc_name isEqualToString:binaryName]) {
                pid_t pid = [process[@"pid"] intValue];
                NSLog(@"[trolldecrypt] Found app PID: %d (existing), killing...", pid);
                kill(pid, SIGKILL);
                break;
            }
        }
        usleep(300000); // 300ms

        NSLog(@"[trolldecrypt] lldb --waitfor for '%@'...", binaryName);
        pid_t lldb_pid = attachLLDBToProcessByName([binaryName UTF8String], -1);
        if (lldb_pid <= 0) {
            NSLog(@"[trolldecrypt] Failed to attach lldb: %@", g_lastDecryptionError);
            NSString *errMsg = g_lastDecryptionError ? [NSString stringWithFormat:@"Failed to start LLDB attach process.\n\nDetails:\n%@", g_lastDecryptionError] : @"Failed to start LLDB attach process.";
            showResultAlert(@"Error: LLDB", errMsg, nil, NO);
            return;
        }

        NSLog(@"[trolldecrypt] Launching app via SpringBoard in suspended state...");
        [[UIApplication sharedApplication] launchApplicationWithIdentifier:bundleID suspended:YES];

        // Wait for LLDB to catch the process
        BOOL caught = NO;
        NSTimeInterval startWait = [NSDate timeIntervalSinceReferenceDate];
        while ([NSDate timeIntervalSinceReferenceDate] - startWait < 30.0) {
            NSString *logContent = [NSString stringWithContentsOfFile:getLogPath() encoding:NSUTF8StringEncoding error:nil];
            if (logContent && ([logContent containsString:@"Architecture set to"] ||
                               [logContent containsString:@"Process "] ||
                               [logContent containsString:@"stopped"] ||
                               [logContent containsString:@"attached"])) {
                caught = YES;
                NSLog(@"[trolldecrypt] LLDB attach confirmed in log: %@", logContent);
                break;
            }
            usleep(200000); // 200ms
        }
        if (!caught) {
            NSString *logContent = [NSString stringWithContentsOfFile:getLogPath() encoding:NSUTF8StringEncoding error:nil];
            NSLog(@"[trolldecrypt] Warning: LLDB log timeout, current content: %@", logContent);
        }

        // Get PID after LLDB caught it with robust retry loop (up to 15 seconds)
        pid_t pid = -1;
        NSTimeInterval startPidPoll = [NSDate timeIntervalSinceReferenceDate];
        while ([NSDate timeIntervalSinceReferenceDate] - startPidPoll < 15.0) {
            processes = sysctl_ps();
            for (NSDictionary *process in processes) {
                NSString *proc_name = process[@"proc_name"];
                if ([proc_name isEqualToString:binaryName]) {
                    pid = [process[@"pid"] intValue];
                    NSLog(@"[trolldecrypt] Found app PID: %d (paused by LLDB)", pid);
                    break;
                }
            }
            if (pid > 0) break;
            usleep(300000); // 300ms
        }

        if (pid <= 0) {
            NSString *logContent = [NSString stringWithContentsOfFile:getLogPath() encoding:NSUTF8StringEncoding error:nil];
            NSLog(@"[trolldecrypt] Failed to get PID for binary name: %@. LLDB log: %@", binaryName, logContent);
            detachLLDB(lldb_pid);
            showResultAlert(@"Error: -1", [NSString stringWithFormat:@"Failed to get PID for binary: %@\n\nLLDB output:\n%@", binaryName, logContent ?: @"(no log)"], nil, NO);
            return;
        }

        NSLog(@"[trolldecrypt] Successfully caught PID: %d, starting dumpDecrypted...", pid);
        bfinject_rocknroll(pid, name, version, lldb_pid);
    });
}

void decryptApp(NSDictionary *app) {
    decryptAppWithLLDB(app);
}

void decryptAppWithFlexDecrypt(NSDictionary *app) {
    dispatch_async(dispatch_get_main_queue(), ^{
        alertWindow = [[UIWindow alloc] initWithFrame: [UIScreen mainScreen].bounds];
        alertWindow.rootViewController = [UIViewController new];
        alertWindow.windowLevel = UIWindowLevelAlert + 1;
        [alertWindow makeKeyAndVisible];
        
        kw = alertWindow;
        if([kw respondsToSelector:@selector(topmostPresentedViewController)])
            root = [kw performSelector:@selector(topmostPresentedViewController)];
        else
            root = [kw rootViewController];
        root.modalPresentationStyle = UIModalPresentationFullScreen;
    });

    NSLog(@"[trolldecrypt] decrypt with flexdecrypt...");

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSString *bundleID = app[@"bundleID"];
        NSString *name = app[@"name"];
        NSString *version = app[@"version"];
        NSString *executable = app[@"executable"];
        NSString *binaryName = [executable lastPathComponent];

        NSLog(@"[trolldecrypt] bundleID: %@", bundleID);
        NSLog(@"[trolldecrypt] name: %@", name);
        NSLog(@"[trolldecrypt] version: %@", version);
        NSLog(@"[trolldecrypt] executable: %@", executable);
        NSLog(@"[trolldecrypt] binaryName: %@", binaryName);

        // Show progress alert
        dispatch_async(dispatch_get_main_queue(), ^{
            alertController = [UIAlertController
                alertControllerWithTitle:@"Decrypting with FlexDecrypt"
                message:@"Please wait, this will take a few seconds..."
                preferredStyle:UIAlertControllerStyleAlert];
            [root presentViewController:alertController animated:YES completion:nil];
        });

        // Kill running instance of the app if any to avoid collision
        killall(binaryName, NO);

        NSString *cleanName = sanitizeFilename(name);
        NSString *cleanVersion = sanitizeFilename(version);
        NSString *outputPath = [docPath() stringByAppendingPathComponent:[NSString stringWithFormat:@"%@_%@", cleanName, cleanVersion]];

        BOOL success = decryptMachOFile(executable, outputPath);

        if (success && [[NSFileManager defaultManager] fileExistsAtPath:outputPath]) {
            NSLog(@"[trolldecrypt] Successfully saved decrypted binary: %@", outputPath);
            showResultAlert(@"Decryption Complete!", [NSString stringWithFormat:@"Decrypted binary saved to:\n%@", outputPath], outputPath, YES);
        } else {
            NSLog(@"[trolldecrypt] Failed to decrypt binary: %@", executable);
            showResultAlert(@"Decryption Error", [NSString stringWithFormat:@"Failed to decrypt binary:\n%@", binaryName], nil, NO);
        }
    });
}

NSArray *decryptedFileList(void) {
    NSMutableArray *files = [NSMutableArray array];
    NSMutableArray *fileNames = [NSMutableArray array];

    // iterate through all files in the Documents directory
    NSFileManager *fileManager = [NSFileManager defaultManager];
    NSDirectoryEnumerator *directoryEnumerator = [fileManager enumeratorAtPath:docPath()];

    NSString *file;
    while (file = [directoryEnumerator nextObject]) {
        if ([[file pathExtension] isEqualToString:@"ipa"]) {
            NSString *filePath = [[docPath() stringByAppendingPathComponent:file] stringByStandardizingPath];

            NSDictionary *fileAttributes = [fileManager attributesOfItemAtPath:filePath error:nil];
            NSDate *modificationDate = fileAttributes[NSFileModificationDate];

            NSDictionary *fileInfo = @{@"fileName": file, @"modificationDate": modificationDate};
            [files addObject:fileInfo];
        }
    }

    // Sort the array based on modification date
    NSArray *sortedFiles = [files sortedArrayUsingComparator:^NSComparisonResult(id obj1, id obj2) {
        NSDate *date1 = [obj1 objectForKey:@"modificationDate"];
        NSDate *date2 = [obj2 objectForKey:@"modificationDate"];
        return [date2 compare:date1];
    }];

    // Get the file names from the sorted array
    for (NSDictionary *fileInfo in sortedFiles) {
        [fileNames addObject:[fileInfo objectForKey:@"fileName"]];
    }

    return [fileNames copy];
}

NSString *docPath(void) {
    NSError * error = nil;
    [[NSFileManager defaultManager] createDirectoryAtPath:@"/var/mobile/Documents/TrollDecrypt/decrypted" withIntermediateDirectories:YES attributes:nil error:&error];
    if (error != nil) {
        NSLog(@"[trolldecrypt] error creating directory: %@", error);
    }

    return @"/var/mobile/Documents/TrollDecrypt/decrypted";
}

void decryptAppWithPID(pid_t pid) {
    // generate App NSDictionary object to pass into decryptApp()
    // proc_pidpath(self.pid, buffer, sizeof(buffer));
    NSString *message = nil;
    NSString *error = nil;

    dispatch_async(dispatch_get_main_queue(), ^{
        alertWindow = [[UIWindow alloc] initWithFrame: [UIScreen mainScreen].bounds];
        alertWindow.rootViewController = [UIViewController new];
        alertWindow.windowLevel = UIWindowLevelAlert + 1;
        [alertWindow makeKeyAndVisible];
        
        // Show a "Decrypting!" alert on the device and block the UI
            
        kw = alertWindow;
        if([kw respondsToSelector:@selector(topmostPresentedViewController)])
            root = [kw performSelector:@selector(topmostPresentedViewController)];
        else
            root = [kw rootViewController];
        root.modalPresentationStyle = UIModalPresentationFullScreen;
    });

    NSLog(@"[trolldecrypt] pid: %d", pid);

    char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
    proc_pidpath(pid, pathbuf, sizeof(pathbuf));

    NSString *executable = [NSString stringWithUTF8String:pathbuf];
    NSString *path = [executable stringByDeletingLastPathComponent];
    NSDictionary *infoPlist = [NSDictionary dictionaryWithContentsOfFile:[path stringByAppendingPathComponent:@"Info.plist"]];
    NSString *bundleID = infoPlist[@"CFBundleIdentifier"];

    if (!bundleID) {
        error = @"Error: -2";
        message = [NSString stringWithFormat:@"Failed to get bundle id for pid: %d", pid];
    }

    LSApplicationProxy *app = [LSApplicationProxy applicationProxyForIdentifier:bundleID];
    if (!app) {
        error = @"Error: -3";
        message = [NSString stringWithFormat:@"Failed to get LSApplicationProxy for bundle id: %@", bundleID];
    }

    if (message) {
        dispatch_async(dispatch_get_main_queue(), ^{
            [alertController dismissViewControllerAnimated:NO completion:nil];
            NSLog(@"[trolldecrypt] failed to get bundleid for pid: %d", pid);

            errorController = [UIAlertController alertControllerWithTitle:error message:message preferredStyle:UIAlertControllerStyleAlert];
            UIAlertAction *okAction = [UIAlertAction actionWithTitle:NSLocalizedString(@"Ok", @"Ok") style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
                NSLog(@"[trolldecrypt] Ok action");
                [errorController dismissViewControllerAnimated:NO completion:nil];
                [kw removeFromSuperview];
                kw.hidden = YES;
            }];

            [errorController addAction:okAction];
            [root presentViewController:errorController animated:YES completion:nil];
        });
    }

    NSLog(@"[trolldecrypt] app: %@", app);

    NSDictionary *appInfo = @{
        @"bundleID":bundleID,
        @"name":[app atl_nameToDisplay],
        @"version":[app atl_shortVersionString],
        @"executable":executable
    };

    NSLog(@"[trolldecrypt] appInfo: %@", appInfo);

    dispatch_async(dispatch_get_main_queue(), ^{
        [alertController dismissViewControllerAnimated:NO completion:nil];
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Decrypt" message:[NSString stringWithFormat:@"Decrypt %@?", appInfo[@"name"]] preferredStyle:UIAlertControllerStyleAlert];
        UIAlertAction *cancel = [UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil];
        UIAlertAction *decrypt = [UIAlertAction actionWithTitle:@"Yes" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
            decryptApp(appInfo);
        }];

        [alert addAction:decrypt];
        [alert addAction:cancel];
        
        [root presentViewController:alert animated:YES completion:nil];
    });
}

// void github_fetchLatedVersion(NSString *repo, void (^completionHandler)(NSString *latestVersion)) {
//     NSString *urlString = [NSString stringWithFormat:@"https://api.github.com/repos/%@/releases/latest", repo];
//     NSURL *url = [NSURL URLWithString:urlString];

//     NSURLSessionDataTask *task = [[NSURLSession sharedSession] dataTaskWithURL:url completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
//         if (!error) {
//             if ([response isKindOfClass:[NSHTTPURLResponse class]]) {
//                 NSError *jsonError;
//                 NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:&jsonError];

//                 if (!jsonError) {
//                     NSString *version = [json[@"tag_name"] stringByReplacingOccurrencesOfString:@"v" withString:@""];
//                     completionHandler(version);
//                 }
//             }
//         }
//     }];

//     [task resume];
// }

void fetchLatestTrollDecryptVersion(void (^completionHandler)(NSString *version)) {
    //github_fetchLatedVersion(@"donato-fiore/TrollDecrypt", completionHandler);
}

NSString *trollDecryptVersion(void) {
    return [NSBundle.mainBundle objectForInfoDictionaryKey:@"CFBundleVersion"];
}

void createIPAWithFlexDecrypt(NSDictionary *app, NSString *decryptedBinaryPath) {
    NSString *cleanName = sanitizeFilename(app[@"name"]);
    NSString *cleanVersion = sanitizeFilename(app[@"version"]);
    NSString *executable = app[@"executable"];
    NSString *binaryName = [executable lastPathComponent];
    
    // Get app path
    NSString *appPath = [executable stringByDeletingLastPathComponent];
    NSString *docPathStr = docPath();
    
    // Create IPA structure in secure temp directory
    NSString *ipaDir = createSecureTempDir(cleanName);
    if (!ipaDir) {
        ipaDir = [NSString stringWithFormat:@"%@/ipa_%lu", docPathStr, (unsigned long)[[NSDate date] timeIntervalSince1970]];
    }
    NSString *payloadDir = [NSString stringWithFormat:@"%@/Payload", ipaDir];
    NSString *appDirName = [appPath lastPathComponent];
    NSString *appCopyDir = [NSString stringWithFormat:@"%@/%@", payloadDir, appDirName];
    NSString *ipaFile = [NSString stringWithFormat:@"%@/%@_%@_decrypted.ipa", docPathStr, cleanName, cleanVersion];
    
    NSFileManager *fm = [NSFileManager defaultManager];
    NSError *error;
    
    // Clean up previous files
    [fm removeItemAtPath:ipaFile error:nil];
    [fm removeItemAtPath:ipaDir error:nil];
    
    // Ensure app copy directory doesn't exist - force remove with error checking
    if ([fm fileExistsAtPath:appCopyDir]) {
        NSLog(@"[trolldecrypt] Removing existing app copy directory: %@", appCopyDir);
        NSError *removeError;
        [fm removeItemAtPath:appCopyDir error:&removeError];
        if (removeError) {
            NSLog(@"[trolldecrypt] Warning: Could not remove existing directory: %@", removeError);
        }
    }
    
    // Create directories
    [fm createDirectoryAtPath:appCopyDir withIntermediateDirectories:YES attributes:nil error:&error];
    if (error) {
        NSLog(@"[trolldecrypt] Error creating app copy directory: %@", error);
        return;
    }
    
    NSLog(@"[trolldecrypt] Copying app from %@ to %@", appPath, appCopyDir);
    
    // Copy entire app directory
    [fm copyItemAtPath:appPath toPath:appCopyDir error:&error];
    if (error) {
        NSLog(@"[trolldecrypt] Error copying app directory: %@", error);
        // Try alternative approach - copy contents instead of directory
        NSLog(@"[trolldecrypt] Trying alternative copy approach...");
        [fm removeItemAtPath:appCopyDir error:nil];
        [fm createDirectoryAtPath:appCopyDir withIntermediateDirectories:YES attributes:nil error:nil];
        
        // Get all items in the source app directory
        NSArray *sourceItems = [fm contentsOfDirectoryAtPath:appPath error:nil];
        for (NSString *item in sourceItems) {
            NSString *sourceItemPath = [appPath stringByAppendingPathComponent:item];
            NSString *destItemPath = [appCopyDir stringByAppendingPathComponent:item];
            [fm copyItemAtPath:sourceItemPath toPath:destItemPath error:nil];
        }
        NSLog(@"[trolldecrypt] Alternative copy approach completed");
    }
    
    // Replace the executable with decrypted version
    NSString *targetExecutable = [appCopyDir stringByAppendingPathComponent:binaryName];
    
    // Force remove existing executable
    if ([fm fileExistsAtPath:targetExecutable]) {
        NSLog(@"[trolldecrypt] Removing existing executable: %@", targetExecutable);
        NSError *removeError;
        [fm removeItemAtPath:targetExecutable error:&removeError];
        if (removeError) {
            NSLog(@"[trolldecrypt] Warning: Could not remove existing executable: %@", removeError);
        }
    }
    
    // Copy decrypted executable
    [fm copyItemAtPath:decryptedBinaryPath toPath:targetExecutable error:&error];
    if (error) {
        NSLog(@"[trolldecrypt] Error replacing executable: %@", error);
        // Try alternative approach - use NSData to force overwrite
        NSLog(@"[trolldecrypt] Trying alternative executable replacement...");
        NSData *decryptedData = [NSData dataWithContentsOfFile:decryptedBinaryPath];
        if (decryptedData) {
            BOOL writeSuccess = [decryptedData writeToFile:targetExecutable atomically:YES];
            if (writeSuccess) {
                NSLog(@"[trolldecrypt] Alternative executable replacement successful");
                error = nil; // Clear error since we succeeded
            } else {
                NSLog(@"[trolldecrypt] Alternative executable replacement failed");
            }
        } else {
            NSLog(@"[trolldecrypt] Could not read decrypted data");
        }
        
        if (error) {
            [fm removeItemAtPath:ipaDir error:nil];
            dispatch_async(dispatch_get_main_queue(), ^{
                [alertController dismissViewControllerAnimated:NO completion:nil];
                errorController = [UIAlertController alertControllerWithTitle:@"Packaging Error"
                    message:[NSString stringWithFormat:@"Failed to copy decrypted binary: %@", error.localizedDescription]
                    preferredStyle:UIAlertControllerStyleAlert];
                UIAlertAction *okAction = [UIAlertAction actionWithTitle:@"Ok" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
                    [errorController dismissViewControllerAnimated:NO completion:nil];
                    [kw removeFromSuperview];
                    kw.hidden = YES;
                }];
                [errorController addAction:okAction];
                [root presentViewController:errorController animated:YES completion:nil];
            });
            return;
        }
    }
    
    // Set POSIX permissions 0755 on decrypted executable
    [fm setAttributes:@{NSFilePosixPermissions: @0755} ofItemAtPath:targetExecutable error:nil];

    // Verify bundle structure has Info.plist to avoid TrollStore error 180
    NSString *plistCheck = [appCopyDir stringByAppendingPathComponent:@"Info.plist"];
    if (![fm fileExistsAtPath:plistCheck]) {
        NSLog(@"[trolldecrypt] Warning: Info.plist missing in target bundle %@", appCopyDir);
        [fm removeItemAtPath:ipaDir error:nil];
        dispatch_async(dispatch_get_main_queue(), ^{
            [alertController dismissViewControllerAnimated:NO completion:nil];
            errorController = [UIAlertController alertControllerWithTitle:@"Packaging Error"
                message:@"Corrupted bundle structure: Info.plist not found in app payload."
                preferredStyle:UIAlertControllerStyleAlert];
            UIAlertAction *okAction = [UIAlertAction actionWithTitle:@"Ok" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
                [errorController dismissViewControllerAnimated:NO completion:nil];
                [kw removeFromSuperview];
                kw.hidden = YES;
            }];
            [errorController addAction:okAction];
            [root presentViewController:errorController animated:YES completion:nil];
        });
        return;
    }
    
    NSLog(@"[trolldecrypt] Replaced executable with decrypted version");
    
    // Create IPA file
    NSLog(@"[trolldecrypt] Creating IPA file: %@", ipaFile);
    BOOL success = [SSZipArchive createZipFileAtPath:ipaFile 
                                withContentsOfDirectory:ipaDir
                                keepParentDirectory:NO 
                                compressionLevel:1
                                password:nil
                                AES:NO
                                progressHandler:nil];
    
    if (success) {
        NSLog(@"[trolldecrypt] IPA created successfully: %@", ipaFile);
        
        // Clean up temporary files
        [fm removeItemAtPath:ipaDir error:nil];
        
        // Show success message
        dispatch_async(dispatch_get_main_queue(), ^{
            [alertController dismissViewControllerAnimated:NO completion:nil];
            
            doneController = [UIAlertController alertControllerWithTitle:@"FlexDecrypt Complete!" 
                message:[NSString stringWithFormat:@"IPA file saved to:\n%@\n\nDecrypted using FlexDecrypt!", ipaFile] 
                preferredStyle:UIAlertControllerStyleAlert];
            
            UIAlertAction *okAction = [UIAlertAction actionWithTitle:@"Ok" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
                [kw removeFromSuperview];
                kw.hidden = YES;
            }];
            [doneController addAction:okAction];
            
            if ([[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:@"filza://"]]) {
                UIAlertAction *openAction = [UIAlertAction actionWithTitle:@"Show in Filza" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
                    [kw removeFromSuperview];
                    kw.hidden = YES;
                    
                    NSString *urlString = [NSString stringWithFormat:@"filza://view%@", ipaFile];
                    [[UIApplication sharedApplication] openURL:[NSURL URLWithString:urlString] options:@{} completionHandler:nil];
                }];
                [doneController addAction:openAction];
            }
            
            [root presentViewController:doneController animated:YES completion:nil];
        });
    } else {
        NSLog(@"[trolldecrypt] Failed to create IPA file");
        
        dispatch_async(dispatch_get_main_queue(), ^{
            [alertController dismissViewControllerAnimated:NO completion:nil];
            errorController = [UIAlertController alertControllerWithTitle:@"FlexDecrypt Error" 
                message:@"Failed to create IPA file" 
                preferredStyle:UIAlertControllerStyleAlert];
            UIAlertAction *okAction = [UIAlertAction actionWithTitle:@"Ok" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
                [errorController dismissViewControllerAnimated:NO completion:nil];
                [kw removeFromSuperview];
                kw.hidden = YES;
            }];
            [errorController addAction:okAction];
            [root presentViewController:errorController animated:YES completion:nil];
        });
    }
}

// Enhanced decryption functions for all mach-o files in an app
void decryptAllMachOInApp(NSDictionary *app) {
    NSString *bundleID = app[@"bundleID"];
    NSString *name = app[@"name"];
    NSString *version = app[@"version"];
    NSString *cleanName = sanitizeFilename(name);
    NSString *cleanVersion = sanitizeFilename(version);
    
    // Show UI alert
    dispatch_async(dispatch_get_main_queue(), ^{
        alertWindow = [[UIWindow alloc] initWithFrame: [UIScreen mainScreen].bounds];
        alertWindow.rootViewController = [UIViewController new];
        alertWindow.windowLevel = UIWindowLevelAlert + 1;
        [alertWindow makeKeyAndVisible];
        
        kw = alertWindow;
        if([kw respondsToSelector:@selector(topmostPresentedViewController)])
            root = [kw performSelector:@selector(topmostPresentedViewController)];
        else
            root = [kw rootViewController];
        root.modalPresentationStyle = UIModalPresentationFullScreen;
        
        // Show progress alert
        alertController = [UIAlertController
            alertControllerWithTitle:@"Decrypting All Mach-O Files"
            message:@"Please wait, this will take a few minutes..."
            preferredStyle:UIAlertControllerStyleAlert];
        [root presentViewController:alertController animated:YES completion:nil];
    });
    
    NSLog(@"[trolldecrypt] Starting comprehensive decryption for %@", name);
    if (app[@"executable"]) {
        killall([app[@"executable"] lastPathComponent], NO);
    }
    
    // Dispatch heavy operations to background thread to avoid freezing UI
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        // Get the app bundle path
        LSApplicationProxy *appProxy = [LSApplicationProxy applicationProxyForIdentifier:bundleID];
        if (!appProxy) {
            NSLog(@"[trolldecrypt] Failed to get app proxy for %@", bundleID);
            showResultAlert(@"Error", [NSString stringWithFormat:@"Failed to get app proxy for %@", bundleID], nil, NO);
            return;
        }
        
        NSString *appPath = [appProxy bundleURL].path;
        if (!appPath) {
            NSLog(@"[trolldecrypt] Failed to get app path for %@", bundleID);
            showResultAlert(@"Error", [NSString stringWithFormat:@"Failed to get app path for %@", bundleID], nil, NO);
            return;
        }
        
        NSLog(@"[trolldecrypt] App path: %@", appPath);
        
        // Find all mach-o files in the app
        NSArray *machOFiles = findAllMachOFiles(appPath);
        NSLog(@"[trolldecrypt] Found %lu mach-o files", (unsigned long)machOFiles.count);
        
        if (machOFiles.count == 0) {
            NSLog(@"[trolldecrypt] No mach-o files found in %@", appPath);
            showResultAlert(@"Error", [NSString stringWithFormat:@"No mach-o files found in %@", appPath], nil, NO);
            return;
        }
        
        // Create secure temporary working directory
        NSString *tempDir = createSecureTempDir(cleanName);
        if (!tempDir) {
            tempDir = [NSTemporaryDirectory() stringByAppendingPathComponent:[NSString stringWithFormat:@"%@_decrypt_work", cleanName]];
        }
        NSFileManager *fm = [NSFileManager defaultManager];
        [fm removeItemAtPath:tempDir error:nil];
        [fm createDirectoryAtPath:tempDir withIntermediateDirectories:YES attributes:nil error:nil];
        
        // Copy the entire app bundle to temp directory
        NSString *tempAppPath = [tempDir stringByAppendingPathComponent:[appPath lastPathComponent]];
        NSError *copyError;
        if (![fm copyItemAtPath:appPath toPath:tempAppPath error:&copyError]) {
            NSLog(@"[trolldecrypt] Failed to copy app bundle: %@", copyError.localizedDescription);
            [fm removeItemAtPath:tempDir error:nil];
            showResultAlert(@"Error", [NSString stringWithFormat:@"Failed to copy app bundle: %@", copyError.localizedDescription], nil, NO);
            return;
        }
        
        NSLog(@"[trolldecrypt] Copied app bundle to: %@", tempAppPath);
        
        // Decrypt each mach-o file and replace it in the temp app bundle
        int failedCount = 0;
        int skippedCount = 0;
        int decryptedCount = 0;
        for (NSString *machOFile in machOFiles) {
            NSString *relativePath = [machOFile substringFromIndex:appPath.length + 1];
            NSString *tempMachOPath = [tempAppPath stringByAppendingPathComponent:relativePath];
            
            // Check if binary is actually FairPlay encrypted
            if (!isMachOEncrypted(machOFile)) {
                NSLog(@"[trolldecrypt] Skipping %@ (already decrypted or unencrypted, cryptid == 0)", relativePath);
                [fm setAttributes:@{NSFilePosixPermissions: @0755} ofItemAtPath:tempMachOPath error:nil];
                skippedCount++;
                continue;
            }
            
            NSLog(@"[trolldecrypt] Decrypting encrypted binary: %@", relativePath);
            if (!decryptMachOFile(machOFile, tempMachOPath)) {
                failedCount++;
            } else {
                decryptedCount++;
            }
        }
        
        // Create IPA from the modified app bundle
        NSString *ipaPath = [docPath() stringByAppendingPathComponent:[NSString stringWithFormat:@"%@_%@_decrypted.ipa", cleanName, cleanVersion]];
        BOOL ipaSuccess = createIPAFromAppBundle(tempAppPath, ipaPath);
        
        // Clean up temp directory
        [fm removeItemAtPath:tempDir error:nil];
        
        if (failedCount > 0) {
            NSLog(@"[trolldecrypt] Decryption failed for %d binaries", failedCount);
            [fm removeItemAtPath:ipaPath error:nil];
            NSString *errMsg = [NSString stringWithFormat:@"Decryption failed for %d Mach-O binaries.\n\nDetails:\n%@", failedCount, g_lastDecryptionError ?: @"Unknown error"];
            showResultAlert(@"Decryption Failed", errMsg, nil, NO);
        } else if (ipaSuccess && [fm fileExistsAtPath:ipaPath]) {
            NSLog(@"[trolldecrypt] Comprehensive decryption completed for %@", name);
            NSLog(@"[trolldecrypt] IPA created at: %@", ipaPath);
            NSString *msg = [NSString stringWithFormat:@"IPA file saved to:\n%@\n\n(Processed %lu Mach-O files: %d decrypted, %d unencrypted)", ipaPath, (unsigned long)machOFiles.count, decryptedCount, skippedCount];
            showResultAlert(@"Decryption Complete!", msg, ipaPath, YES);
        } else {
            NSLog(@"[trolldecrypt] Failed to create IPA file at: %@", ipaPath);
            showResultAlert(@"Packaging Error", @"Failed to create IPA file archive.", nil, NO);
        }
    });
}

NSArray *findAllMachOFiles(NSString *appPath) {
    NSMutableArray *machOFiles = [NSMutableArray array];
    NSFileManager *fm = [NSFileManager defaultManager];
    
    NSDirectoryEnumerator *enumerator = [fm enumeratorAtPath:appPath];
    NSString *file;
    
    while (file = [enumerator nextObject]) {
        NSString *fullPath = [appPath stringByAppendingPathComponent:file];
        
        // Skip certain directories that we don't want to process
        if ([file containsString:@".app/"] && ![file hasPrefix:[[appPath lastPathComponent] stringByAppendingString:@".app/"]]) {
            [enumerator skipDescendants];
            continue;
        }
        
        // Skip .dSYM directories
        if ([file containsString:@".dSYM/"]) {
            [enumerator skipDescendants];
            continue;
        }
        
        // Skip certain file types that are not mach-o
        NSString *extension = [file pathExtension];
        if ([extension isEqualToString:@"plist"] || 
            [extension isEqualToString:@"png"] || 
            [extension isEqualToString:@"jpg"] || 
            [extension isEqualToString:@"jpeg"] ||
            [extension isEqualToString:@"gif"] ||
            [extension isEqualToString:@"json"] ||
            [extension isEqualToString:@"txt"] ||
            [extension isEqualToString:@"xml"]) {
            continue;
        }
        
        if (isMachOFile(fullPath)) {
            NSLog(@"[trolldecrypt] Found mach-o file: %@", file);
            [machOFiles addObject:fullPath];
        }
    }
    
    return [machOFiles copy];
}

BOOL isMachOFile(NSString *filePath) {
    NSFileManager *fm = [NSFileManager defaultManager];
    
    // Check if file exists and is not a directory
    BOOL isDirectory;
    if (![fm fileExistsAtPath:filePath isDirectory:&isDirectory] || isDirectory) {
        return NO;
    }
    
    // Check file extension
    NSString *extension = [filePath pathExtension];
    NSString *fileName = [filePath lastPathComponent];
    
    // Check for known mach-o extensions
    if ([extension isEqualToString:@"dylib"] || 
        [extension isEqualToString:@"so"] ||
        [fileName hasPrefix:@"lib"] ||
        [fileName hasSuffix:@".so"]) {
        return YES;
    }
    
    // Check for framework binaries (no extension, inside .framework)
    if ([extension isEqualToString:@""] && [filePath containsString:@".framework/"]) {
        // This is likely a framework binary
        return YES;
    }
    
    // Check if it's an executable (no extension)
    if ([extension isEqualToString:@""]) {
        // Read first 4 bytes to check for mach-o magic
        NSFileHandle *fileHandle = [NSFileHandle fileHandleForReadingAtPath:filePath];
        if (fileHandle) {
            NSData *magicData = [fileHandle readDataOfLength:4];
            [fileHandle closeFile];
            
            if (magicData.length >= 4) {
                const uint8_t *bytes = (const uint8_t *)magicData.bytes;
                uint32_t magic = *(uint32_t *)bytes;
                
                // Check for mach-o magic numbers
                if (magic == 0xfeedface || magic == 0xfeedfacf || magic == 0xcffaedfe || magic == 0xcefaedfe) {
                    return YES;
                }
            }
        }
    }
    
    return NO;
}

BOOL decryptMachOFile(NSString *filePath, NSString *outputPath) {
    if (!filePath || !outputPath) return NO;
    NSLog(@"[trolldecrypt] Decrypting mach-o file: %@ -> %@", filePath, outputPath);
    
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *fileName = [filePath lastPathComponent];
    NSString *outputDir = [outputPath stringByDeletingLastPathComponent];
    [fm createDirectoryAtPath:outputDir withIntermediateDirectories:YES attributes:nil error:nil];
    
    // Ensure flexdecrypt_bin exists and is executable
    NSString *flexdecryptPath = resolveToolPath(@"flexdecrypt_bin", @"/Applications/TrollDecrypt.app/flexdecrypt_bin");
    if (!flexdecryptPath || ![fm fileExistsAtPath:flexdecryptPath]) {
        flexdecryptPath = [[NSBundle mainBundle] pathForResource:@"flexdecrypt_bin" ofType:nil];
    }
    if (!flexdecryptPath || ![fm fileExistsAtPath:flexdecryptPath]) {
        flexdecryptPath = @"./flexdecrypt_bin";
    }
    
    // Make sure it has execute permissions
    chmod([flexdecryptPath UTF8String], 0755);
    
    // Optional dlopen
    NSString *dlopenPath = resolveToolPath(@"dlopentool", @"/usr/local/bin/dlopentool");
    if (dlopenPath && [fm fileExistsAtPath:dlopenPath]) {
        chmod([dlopenPath UTF8String], 0755);
        NSString *dlopenStdOut = nil;
        NSString *dlopenStdErr = nil;
        spawnRoot(dlopenPath, @[filePath], &dlopenStdOut, &dlopenStdErr);
    }
    
    // Use an isolated temporary destination path for flexdecrypt output
    NSString *tempDecryptedFile = [outputDir stringByAppendingPathComponent:[NSString stringWithFormat:@".td_dec_%@_%u", fileName, arc4random_uniform(100000)]];
    [fm removeItemAtPath:tempDecryptedFile error:nil];
    
    // Helper block to test if a candidate decrypted binary is valid and install it to outputPath
    BOOL (^checkAndInstall)(NSString *candidatePath) = ^BOOL(NSString *candidatePath) {
        if (!candidatePath || ![fm fileExistsAtPath:candidatePath]) return NO;
        
        // Verify candidate file is non-empty and truly decrypted (cryptid == 0)
        NSDictionary *attrs = [fm attributesOfItemAtPath:candidatePath error:nil];
        if ([attrs fileSize] == 0) {
            NSLog(@"[trolldecrypt] Candidate %@ is 0 bytes, ignoring", candidatePath);
            return NO;
        }
        
        if (isMachOEncrypted(candidatePath)) {
            NSLog(@"[trolldecrypt] Candidate %@ is still encrypted (cryptid != 0)", candidatePath);
            return NO;
        }
        
        // Candidate is verified decrypted (cryptid == 0)! Install it to outputPath
        [fm removeItemAtPath:outputPath error:nil];
        NSError *installError = nil;
        if (![fm moveItemAtPath:candidatePath toPath:outputPath error:&installError]) {
            if (![fm copyItemAtPath:candidatePath toPath:outputPath error:&installError]) {
                NSLog(@"[trolldecrypt] Failed to install decrypted binary from %@ to %@: %@", candidatePath, outputPath, installError.localizedDescription);
                return NO;
            }
            [fm removeItemAtPath:candidatePath error:nil];
        }
        
        [fm setAttributes:@{NSFilePosixPermissions: @0755} ofItemAtPath:outputPath error:nil];
        NSLog(@"[trolldecrypt] Successfully installed decrypted Mach-O (cryptid == 0): %@", outputPath);
        return YES;
    };
    
    // Helper to parse "Wrote decrypted image to <path>" from flexdecrypt stdout
    NSString* (^parseStdoutPath)(NSString *outputStr) = ^NSString*(NSString *outputStr) {
        if (!outputStr || ![outputStr containsString:@"Wrote decrypted image to "]) return nil;
        NSArray *lines = [outputStr componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]];
        for (NSString *line in lines) {
            if ([line containsString:@"Wrote decrypted image to "]) {
                NSString *p = [[line componentsSeparatedByString:@"Wrote decrypted image to "] lastObject];
                p = [p stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
                if (p.length > 0) return p;
            }
        }
        return nil;
    };
    
    // Candidate fallback locations if --output was ignored
    NSArray *fallbackLocations = @[
        [NSString stringWithFormat:@"/private/var/tmp/%@", fileName],
        [NSString stringWithFormat:@"/tmp/%@", fileName],
        [NSTemporaryDirectory() stringByAppendingPathComponent:fileName],
        [filePath stringByAppendingString:@".decrypted"],
        [outputPath stringByAppendingString:@".decrypted"]
    ];
    
    // Attempt 1: flexdecrypt <filePath> --output <tempDecryptedFile>
    NSString *stdOut1 = nil;
    NSString *stdErr1 = nil;
    NSLog(@"[trolldecrypt] Attempt 1: %@ %@ --output %@", flexdecryptPath, filePath, tempDecryptedFile);
    int res1 = spawnRoot(flexdecryptPath, @[filePath, @"--output", tempDecryptedFile], &stdOut1, &stdErr1);
    NSLog(@"[trolldecrypt] Attempt 1 exited with %d (stdout: %@, stderr: %@)", res1, stdOut1, stdErr1);
    
    if (checkAndInstall(tempDecryptedFile)) return YES;
    
    NSString *parsedPath1 = parseStdoutPath(stdOut1);
    if (parsedPath1 && checkAndInstall(parsedPath1)) return YES;
    
    for (NSString *cand in fallbackLocations) {
        if (checkAndInstall(cand)) return YES;
    }
    
    // Attempt 2: flexdecrypt --output <tempDecryptedFile> <filePath> (option before argument)
    NSString *stdOut2 = nil;
    NSString *stdErr2 = nil;
    NSLog(@"[trolldecrypt] Attempt 2: %@ --output %@ %@", flexdecryptPath, tempDecryptedFile, filePath);
    int res2 = spawnRoot(flexdecryptPath, @[@"--output", tempDecryptedFile, filePath], &stdOut2, &stdErr2);
    NSLog(@"[trolldecrypt] Attempt 2 exited with %d (stdout: %@, stderr: %@)", res2, stdOut2, stdErr2);
    
    if (checkAndInstall(tempDecryptedFile)) return YES;
    
    NSString *parsedPath2 = parseStdoutPath(stdOut2);
    if (parsedPath2 && checkAndInstall(parsedPath2)) return YES;
    
    for (NSString *cand in fallbackLocations) {
        if (checkAndInstall(cand)) return YES;
    }
    
    // Attempt 3: flexdecrypt <filePath> (default output without --output flag)
    NSString *stdOut3 = nil;
    NSString *stdErr3 = nil;
    NSLog(@"[trolldecrypt] Attempt 3: %@ %@", flexdecryptPath, filePath);
    int res3 = spawnRoot(flexdecryptPath, @[filePath], &stdOut3, &stdErr3);
    NSLog(@"[trolldecrypt] Attempt 3 exited with %d (stdout: %@, stderr: %@)", res3, stdOut3, stdErr3);
    
    NSString *parsedPath3 = parseStdoutPath(stdOut3);
    if (parsedPath3 && checkAndInstall(parsedPath3)) return YES;
    
    for (NSString *cand in fallbackLocations) {
        if (checkAndInstall(cand)) return YES;
    }
    
    // Clean up temporary file
    [fm removeItemAtPath:tempDecryptedFile error:nil];
    
    // Final sanity check: if the file at outputPath is already decrypted
    if ([fm fileExistsAtPath:outputPath] && !isMachOEncrypted(outputPath)) {
        NSLog(@"[trolldecrypt] Target at %@ verified decrypted (cryptid == 0)", outputPath);
        [fm setAttributes:@{NSFilePosixPermissions: @0755} ofItemAtPath:outputPath error:nil];
        return YES;
    }
    
    NSLog(@"[trolldecrypt] ERROR: Decryption failed for Mach-O file: %@", filePath);
    g_lastDecryptionError = [NSString stringWithFormat:@"File: %@\nRes1: %d, err1: %@, out1: %@\nRes2: %d, err2: %@, out2: %@\nRes3: %d, err3: %@, out3: %@",
                             fileName, res1, stdErr1 ?: @"", stdOut1 ?: @"",
                             res2, stdErr2 ?: @"", stdOut2 ?: @"",
                             res3, stdErr3 ?: @"", stdOut3 ?: @""];
    return NO;
}

BOOL createIPAFromAppBundle(NSString *appBundlePath, NSString *ipaPath) {
    NSLog(@"[trolldecrypt] Creating IPA from app bundle: %@", appBundlePath);
    
    NSFileManager *fm = [NSFileManager defaultManager];
    
    // Create dedicated packaging directory
    NSString *baseDir = [appBundlePath stringByDeletingLastPathComponent];
    NSString *packagingDir = [baseDir stringByAppendingPathComponent:@"_ipa_packaging"];
    [fm removeItemAtPath:packagingDir error:nil];
    
    NSString *payloadDir = [packagingDir stringByAppendingPathComponent:@"Payload"];
    [fm createDirectoryAtPath:payloadDir withIntermediateDirectories:YES attributes:nil error:nil];
    
    // Copy app bundle to packagingDir/Payload/<AppName>.app
    NSString *payloadAppPath = [payloadDir stringByAppendingPathComponent:[appBundlePath lastPathComponent]];
    NSError *copyError = nil;
    if (![fm copyItemAtPath:appBundlePath toPath:payloadAppPath error:&copyError]) {
        NSLog(@"[trolldecrypt] Failed to copy app bundle to Payload: %@", copyError.localizedDescription);
        [fm removeItemAtPath:packagingDir error:nil];
        return NO;
    }
    
    // Verify Info.plist in payload app
    NSString *checkPlist = [payloadAppPath stringByAppendingPathComponent:@"Info.plist"];
    if (![fm fileExistsAtPath:checkPlist]) {
        NSLog(@"[trolldecrypt] Failed to create IPA: Info.plist missing in app bundle");
        [fm removeItemAtPath:packagingDir error:nil];
        return NO;
    }

    // Set POSIX permissions 0755 on executables inside payloadAppPath
    NSArray *dirContents = [fm contentsOfDirectoryAtPath:payloadAppPath error:nil];
    for (NSString *item in dirContents) {
        NSString *fullItemPath = [payloadAppPath stringByAppendingPathComponent:item];
        BOOL isDir = NO;
        if ([fm fileExistsAtPath:fullItemPath isDirectory:&isDir] && !isDir) {
            if ([fm isExecutableFileAtPath:fullItemPath] || isMachOFile(fullItemPath)) {
                [fm setAttributes:@{NSFilePosixPermissions: @0755} ofItemAtPath:fullItemPath error:nil];
            }
        }
    }

    // Remove existing destination IPA if any
    [fm removeItemAtPath:ipaPath error:nil];

    // Create IPA using SSZipArchive directly from packagingDir
    // withContentsOfDirectory:packagingDir keepParentDirectory:NO produces exact 'Payload/<AppName>.app/...'
    NSLog(@"[trolldecrypt] Creating IPA file using SSZipArchive: %@", ipaPath);
    BOOL zipSuccess = [SSZipArchive createZipFileAtPath:ipaPath
                                withContentsOfDirectory:packagingDir
                                keepParentDirectory:NO
                                compressionLevel:1
                                password:nil
                                AES:NO
                                progressHandler:nil];

    // Clean up packaging directory
    [fm removeItemAtPath:packagingDir error:nil];

    if (!zipSuccess || ![fm fileExistsAtPath:ipaPath]) {
        NSLog(@"[trolldecrypt] Failed to create IPA with SSZipArchive");
        [fm removeItemAtPath:ipaPath error:nil];
        return NO;
    }

    NSLog(@"[trolldecrypt] IPA created successfully at: %@", ipaPath);
    return YES;
}
