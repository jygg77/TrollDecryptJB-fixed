#import "TDUtils.h"
#import "TDDumpDecrypted.h"
#import "LSApplicationProxy+AltList.h"
#import "SSZipArchive/SSZipArchive.h"
#import "appstoretrollerKiller/TSUtil.h"

#if __has_include(<rootless.h>)
#import <rootless.h>
#else
#define ROOT_PATH_NS(path) path
#endif

static NSString *resolveToolPath(NSString *name, NSString *fallbackPath) {
    NSFileManager *fm = [NSFileManager defaultManager];
    // Check main bundle first
    NSString *bundlePath = [[NSBundle mainBundle] pathForResource:name ofType:nil];
    if (bundlePath && [fm fileExistsAtPath:bundlePath]) {
        return bundlePath;
    }
    // Check rootless / roothide path
    NSString *rootlessPath = ROOT_PATH_NS(fallbackPath);
    if ([fm fileExistsAtPath:rootlessPath]) {
        return rootlessPath;
    }
    // Check raw fallback path
    if ([fm fileExistsAtPath:fallbackPath]) {
        return fallbackPath;
    }
    return nil;
}

#include <mach-o/fat.h>
#include <libkern/OSByteOrder.h>

static NSString *sanitizeFilename(NSString *input) {
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

void decryptApp(NSDictionary *app) {
    // Use flexdecrypt method instead of lldb
    decryptAppWithFlexDecrypt(app);
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

        // Execute flexdecrypt
        NSString *flexdecryptPath = [[NSBundle mainBundle] pathForResource:@"flexdecrypt_bin" ofType:nil];
        if (!flexdecryptPath) {
            flexdecryptPath = @"./flexdecrypt_bin"; // Fallback to current directory
        }
        
        NSLog(@"[trolldecrypt] Using flexdecrypt at: %@", flexdecryptPath);
        NSLog(@"[trolldecrypt] Decrypting binary: %@", executable);
        
        // First, run dlopen on the binary to load its dependencies
        NSLog(@"[trolldecrypt] Running dlopen on %@ to load dependencies", executable);
        NSString *dlopenPath = resolveToolPath(@"dlopentool", @"/usr/local/bin/dlopentool");
        NSFileManager *fm = [NSFileManager defaultManager];
        
        if (dlopenPath && [fm fileExistsAtPath:dlopenPath]) {
            NSString *dlopenStdOut = nil;
            NSString *dlopenStdErr = nil;
            int dlopenResult = spawnRoot(dlopenPath, @[executable], &dlopenStdOut, &dlopenStdErr);
            
            if (dlopenResult == 0) {
                NSLog(@"[trolldecrypt] dlopen completed successfully for %@", executable);
                if (dlopenStdOut && dlopenStdOut.length > 0) {
                    NSLog(@"[trolldecrypt] dlopen stdout: %@", dlopenStdOut);
                }
            } else {
                NSLog(@"[trolldecrypt] dlopen failed for %@ (exit code: %d): %@", executable, dlopenResult, dlopenStdErr);
            }
        } else {
            NSLog(@"[trolldecrypt] dlopentool not found, skipping dlopen step");
        }
        
        // Run flexdecrypt command
        NSString *stdOut = nil;
        NSString *stdErr = nil;
        int result = spawnRoot(flexdecryptPath, @[executable], &stdOut, &stdErr);
        
        NSLog(@"[trolldecrypt] flexdecrypt result: %d", result);
        if (stdOut && stdOut.length > 0) {
            NSLog(@"[trolldecrypt] stdout: %@", stdOut);
        }
        if (stdErr && stdErr.length > 0) {
            NSLog(@"[trolldecrypt] stderr: %@", stdErr);
        }
        
        if (result != 0) {
            NSLog(@"[trolldecrypt] flexdecrypt failed: %d, stderr: %@", result, stdErr);
            NSString *errMessage = (stdErr && stdErr.length > 0) ? stdErr : [NSString stringWithFormat:@"FlexDecrypt returned exit code %d", result];
            showResultAlert(@"FlexDecrypt Error", errMessage, nil, NO);
            return;
        }
        
        // Find the decrypted file in /tmp
        NSString *decryptedPath = [NSString stringWithFormat:@"/tmp/%@", binaryName];
        
        if (![fm fileExistsAtPath:decryptedPath]) {
            NSLog(@"[trolldecrypt] decrypted file not found at: %@", decryptedPath);
            showResultAlert(@"FlexDecrypt Error", [NSString stringWithFormat:@"Decrypted file not found at: %@", decryptedPath], nil, NO);
            return;
        }
        
        NSLog(@"[trolldecrypt] Found decrypted file at: %@", decryptedPath);
        
        // Save decrypted binary to documents directory
        NSString *cleanName = sanitizeFilename(name);
        NSString *cleanVersion = sanitizeFilename(version);
        NSString *outputPath = [docPath() stringByAppendingPathComponent:[NSString stringWithFormat:@"%@_%@", cleanName, cleanVersion]];
        
        // Force remove existing file if it exists to allow overwrite
        if ([fm fileExistsAtPath:outputPath]) {
            NSLog(@"[trolldecrypt] Removing existing file to allow overwrite: %@", outputPath);
            NSError *removeError;
            [fm removeItemAtPath:outputPath error:&removeError];
            if (removeError) {
                NSLog(@"[trolldecrypt] Warning: Could not remove existing file: %@", removeError.localizedDescription);
            }
        }
        
        NSError *copyError;
        if ([fm copyItemAtPath:decryptedPath toPath:outputPath error:&copyError]) {
            NSLog(@"[trolldecrypt] Successfully saved decrypted binary: %@", outputPath);
            [fm setAttributes:@{NSFilePosixPermissions: @0755} ofItemAtPath:outputPath error:nil];
            [fm removeItemAtPath:decryptedPath error:nil];
            showResultAlert(@"Decryption Complete!", [NSString stringWithFormat:@"Decrypted binary saved to:\n%@", outputPath], outputPath, YES);
        } else {
            NSLog(@"[trolldecrypt] Failed to copy decrypted file: %@", copyError.localizedDescription);
            showResultAlert(@"Copy Error", [NSString stringWithFormat:@"Failed to save decrypted file: %@", copyError.localizedDescription], nil, NO);
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
        
        if (ipaSuccess && [fm fileExistsAtPath:ipaPath]) {
            NSLog(@"[trolldecrypt] Comprehensive decryption completed for %@", name);
            NSLog(@"[trolldecrypt] IPA created at: %@", ipaPath);
            NSString *msg = [NSString stringWithFormat:@"IPA file saved to:\n%@\n\n(Processed %lu Mach-O files: %d decrypted, %d unencrypted)", ipaPath, (unsigned long)machOFiles.count, decryptedCount, skippedCount];
            if (failedCount > 0) {
                msg = [NSString stringWithFormat:@"IPA created with warnings:\n%@\n\n(%d decrypted, %d unencrypted, %d failed)", ipaPath, decryptedCount, skippedCount, failedCount];
            }
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
    NSLog(@"[trolldecrypt] Decrypting mach-o file: %@", filePath);
    
    NSFileManager *fm = [NSFileManager defaultManager];
    
    // First, run dlopen on the binary to load its dependencies
    NSString *dlopenPath = resolveToolPath(@"dlopentool", @"/usr/local/bin/dlopentool");
    if (dlopenPath && [fm fileExistsAtPath:dlopenPath]) {
        NSString *dlopenStdOut = nil;
        NSString *dlopenStdErr = nil;
        spawnRoot(dlopenPath, @[filePath], &dlopenStdOut, &dlopenStdErr);
    }
    
    // Use flexdecrypt to decrypt the file
    NSString *flexdecryptPath = [[NSBundle mainBundle] pathForResource:@"flexdecrypt_bin" ofType:nil];
    if (!flexdecryptPath) {
        flexdecryptPath = @"./flexdecrypt_bin";
    }
    
    // Run flexdecrypt
    NSString *stdOut = nil;
    NSString *stdErr = nil;
    int result = spawnRoot(flexdecryptPath, @[filePath], &stdOut, &stdErr);
    
    if (result != 0) {
        NSLog(@"[trolldecrypt] FlexDecrypt failed for %@ (code %d): %@", filePath, result, stdErr);
        return NO;
    }
    
    // Find the decrypted file (usually in /tmp with the same name)
    NSString *decryptedPath = [NSString stringWithFormat:@"/tmp/%@", [filePath lastPathComponent]];
    
    if ([fm fileExistsAtPath:decryptedPath]) {
        NSString *outputDir = [outputPath stringByDeletingLastPathComponent];
        [fm createDirectoryAtPath:outputDir withIntermediateDirectories:YES attributes:nil error:nil];
        [fm removeItemAtPath:outputPath error:nil];
        
        NSError *error;
        if ([fm copyItemAtPath:decryptedPath toPath:outputPath error:&error]) {
            NSLog(@"[trolldecrypt] Successfully decrypted: %@ -> %@", filePath, outputPath);
            [fm setAttributes:@{NSFilePosixPermissions: @0755} ofItemAtPath:outputPath error:nil];
            [fm removeItemAtPath:decryptedPath error:nil];
            return YES;
        } else {
            NSLog(@"[trolldecrypt] Failed to copy decrypted file: %@", error.localizedDescription);
            [fm removeItemAtPath:decryptedPath error:nil];
            return NO;
        }
    } else {
        NSLog(@"[trolldecrypt] Decrypted file not found at: %@", decryptedPath);
        return NO;
    }
}

BOOL createIPAFromAppBundle(NSString *appBundlePath, NSString *ipaPath) {
    NSLog(@"[trolldecrypt] Creating IPA from app bundle: %@", appBundlePath);
    
    NSFileManager *fm = [NSFileManager defaultManager];
    
    // Create Payload directory in the same directory as the app bundle
    NSString *workDir = [appBundlePath stringByDeletingLastPathComponent];
    NSString *payloadDir = [workDir stringByAppendingPathComponent:@"Payload"];
    [fm removeItemAtPath:payloadDir error:nil];
    [fm createDirectoryAtPath:payloadDir withIntermediateDirectories:YES attributes:nil error:nil];
    
    // Copy app bundle to Payload directory
    NSString *payloadAppPath = [payloadDir stringByAppendingPathComponent:[appBundlePath lastPathComponent]];
    NSError *copyError;
    if (![fm copyItemAtPath:appBundlePath toPath:payloadAppPath error:&copyError]) {
        NSLog(@"[trolldecrypt] Failed to copy app bundle to Payload: %@", copyError.localizedDescription);
        [fm removeItemAtPath:payloadDir error:nil];
        return NO;
    }
    
    // Verify Info.plist in payload app
    NSString *checkPlist = [payloadAppPath stringByAppendingPathComponent:@"Info.plist"];
    if (![fm fileExistsAtPath:checkPlist]) {
        NSLog(@"[trolldecrypt] Failed to create IPA: Info.plist missing in app bundle");
        [fm removeItemAtPath:payloadDir error:nil];
        return NO;
    }

    // Set POSIX permissions 0755 on executables inside payloadAppPath
    NSArray *dirContents = [fm contentsOfDirectoryAtPath:payloadAppPath error:nil];
    for (NSString *item in dirContents) {
        NSString *fullItemPath = [payloadAppPath stringByAppendingPathComponent:item];
        BOOL isDir = NO;
        if ([fm fileExistsAtPath:fullItemPath isDirectory:&isDir] && !isDir) {
            if ([fm isExecutableFileAtPath:fullItemPath]) {
                [fm setAttributes:@{NSFilePosixPermissions: @0755} ofItemAtPath:fullItemPath error:nil];
            }
        }
    }

    // Remove existing destination IPA if any
    [fm removeItemAtPath:ipaPath error:nil];

    // Create IPA using SSZipArchive directly (no external /usr/bin/zip dependency!)
    NSLog(@"[trolldecrypt] Creating IPA file using SSZipArchive: %@", ipaPath);
    BOOL zipSuccess = [SSZipArchive createZipFileAtPath:ipaPath
                                withContentsOfDirectory:workDir
                                keepParentDirectory:NO
                                compressionLevel:1
                                password:nil
                                AES:NO
                                progressHandler:nil];

    // Clean up Payload directory
    [fm removeItemAtPath:payloadDir error:nil];

    if (!zipSuccess || ![fm fileExistsAtPath:ipaPath]) {
        NSLog(@"[trolldecrypt] Failed to create IPA with SSZipArchive");
        [fm removeItemAtPath:ipaPath error:nil];
        return NO;
    }

    NSLog(@"[trolldecrypt] IPA created successfully at: %@", ipaPath);
    return YES;
}