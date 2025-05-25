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
#include <sys/sendfile.h>
#include <sys/time.h>
#ifdef HAVE_PTHREAD
#include <pthread.h>
#endif

/* Maximum pathname lenght dsync can handle. FIXME: make dynamic */
#define MAXLEN 16384

/* Entry is a single entry in a directory */
typedef struct {
    char *name;
    struct stat stat;
    char *link;
    int error;                  /* If there was a IO error with stat() */
    struct JobStruct *job;      /* If this entry has a job associated to it */
} Entry;


/* We keep the fd of all directories around until the directories are processed to be able to use 
   openat() and to make sure that symlink or mv race conditions do not take us to a wrong directory */
typedef struct DirectoryStruct {
    int magick; /* 0xDADDAD to catch a race, 0xDEADBEEF to mark a zombie */
    DIR *handle;
    struct DirectoryStruct *parent;
    char *name;
    int entries;
    int refs; 
    Entry *array;
} Directory;

typedef struct {
    int dirs_scanned;
    int entries_scanned;
    int dirs_skipped;
    int files_skipped;
    
    int pre_scan_hits;
    int pre_scan_wait_hits;
    int pre_scan_misses;
    int pre_scan_dirs;
    int pre_scan_allocated;
    int pre_scan_used;

    int jobs;
    int maxjobs;

    int dirs_active;
    int dirs_active_max;
} Scans;
extern Scans scans;
typedef struct JobStruct Job;

typedef int (JobCallback) (Directory *from,
		 const char *source, 
		 Directory *to,
		 const char *target,
                 off_t offset);

#if 0
Directory *scan_directory(const char *name, Directory *parent);
#endif
void show_error(const char *why, const char *file);
Directory *pre_scan_directory(const char *dir, Directory *parent);
void start_job_threads(int threads);
void d_freedir(Directory *dir);

Job *submit_job(Directory *from, const char *source, Directory *to, const char *target, off_t offset, JobCallback *callback);
int wait_for_job(Job *job);

const char *dir_path(const Directory *d);
void show_error_dir(const char *message, const Directory *parent, const char *file);


