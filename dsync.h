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
#include <pthread.h>
#include <stdatomic.h>

/* Maximum pathname lenght dsync can handle. FIXME: make dynamic */
#define MAXLEN 16384

/* Entry is a single entry in a directory */
typedef struct {
    char *name;
    struct stat stat;
    char *link;
    int error;                  /* If there was a IO error with stat() */
    struct JobStruct *job;      /* If this entry has a job associated to it */
    struct DirectoryStruct *dir;
} Entry;

#define DSYNC_JOB_WAIT -123

/* We keep the fd of all directories around until the directories are processed to be able to use 
   openat() and to make sure that symlink or mv race conditions do not take us to a wrong directory */
typedef struct DirectoryStruct {
    int magick; /* 0xDADDAD to catch a race, 0xDEADBEEF to mark a zombie */
    DIR *handle;
    int fd;
    struct stat stat;
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
    int pre_scan_too_late; /* Prescan was too late, the directory was already scanned by another thread */
    int pre_scan_dirs;
    int pre_scan_allocated;
    int pre_scan_used;

    int jobs;
    int queued;
    int maxjobs;

    int dirs_active;
    int entries_active;
    int dirs_active_max;
    int dirs_freed;

    int idle_threads;
} Scans;
extern Scans scans;
typedef struct JobStruct Job;

typedef int (JobCallback) (
                Directory *from,
		Entry *from_entry, 
		Directory *to,
		const char *target,
                off_t offset);

/* It is a useless distraction to deal with out of memory. Just die. */
static inline char *my_strdup(const char *str) {
        char *s=strdup(str);
        if (!s) {
                fprintf(stderr,"strdup() out of memory. Exiting with status 2.\n");
                exit(2);
        }
        return s;
}
static inline void *my_calloc(size_t nmemb, size_t size) {
    void *ptr = calloc(nmemb, size);
    if (!ptr) {
        fprintf(stderr,"Out of memory. Exiting with status 2.\n");
        exit(2);
    }
    return ptr;
}
static inline void *my_malloc(size_t size) {
        return my_calloc(1,size);
}
static inline void *my_realloc(void *ptr, size_t size) {
    void *newptr = realloc(ptr, size);
    if (!newptr) {
        fprintf(stderr, "realloc() out of memory. Exiting with status 2.\n");
        exit(2);
    }
    return newptr;
}

extern int progress;

#define strdup(X) ( use_my_strdup_instead(X) )
Directory *scan_directory(const char *name, Directory *parent);
void show_error(const char *why, const char *file);
Entry *init_entry(Entry * entry, int dfd, char *name);

Directory *pre_scan_directory(Directory *parent, Entry *dir);
void start_job_threads(int threads, Job *job);
void d_freedir(Directory *dir);

Job *submit_job(Directory *from, Entry *source, Directory *to, const char *target, off_t offset, JobCallback *callback);
int wait_for_entry(Entry *job);

const char *dir_path(const Directory *d);
const char *file_path(const Directory *d, const char *f);
void show_error_dir(const char *message, const Directory *parent, const char *file);
int run_any_job();
int print_jobs(FILE *f);
void set_thread_status(const char *file, const char *status);
void show_progress();
int dir_openat(Directory *parent, const char *name);
int dir_getfd(Directory *d);
