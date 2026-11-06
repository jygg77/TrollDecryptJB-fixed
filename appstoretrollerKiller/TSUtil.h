@import Foundation;

extern int spawnRoot(NSString* path, NSArray* args, NSString** stdOut, NSString** stdErr);
extern void killall(NSString* processName, BOOL softly);
extern int available_persona_id(void);
