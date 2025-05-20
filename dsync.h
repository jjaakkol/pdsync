#define _FILE_OFFSET_BITS 64
#define _GNU_SOURCE
#define HAVE_PTHREAD 

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <utime.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <getopt.h>
#include <regex.h>
#include <time.h>
#include <dirent.h>
#ifdef HAVE_PTHREAD
#include <pthread.h>
#endif

/* Maximum pathname lenght dsync can handle. FIXME: make dynamic */
#define MAXLEN 16384

enum EntryState { ENTRY_UNDEF=0, ENTRY_GOOD, 
		  ENTRY_STAT_FAILED, ENTRY_READLINK_FAILED };

typedef struct {
    char *name;
    struct stat stat;
    char *link;
    enum EntryState state;
} Entry;


/* We keep the fd of all directories around until the directories are processed to be able to use 
   openat() and to make sure that symlink or mv race conditions do not take us to a wrong directory */
typedef struct {
    DIR *handle;
    int parentfd;
    int entries;
    Entry *array;
} Directory;

typedef struct {
    int dirs_scanned;
    int entries_scanned;
    int dirs_skipped;
    
    int pre_scan_hits;
    int pre_scan_wait_hits;
    int pre_scan_misses;
    int pre_scan_dirs;
    int pre_scan_allocated;
    int pre_scan_used;
} Scans;
extern Scans scans;

Directory *scan_directory(const char *name, int parentfd);
void show_error(const char *why, const char *file);
Directory *pre_scan_directory(const char *dir,int parentfd);
void *pre_read_loop(void *arg);
void start_pre_scan_thread();
