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

typedef enum { ENTRY_CREATED,   
                ENTRY_INIT,
                ENTRY_READ_QUEUE,
                ENTRY_READING,
                ENTRY_READ_READY,
                ENTRY_SCAN_QUEUE,
                ENTRY_SCAN_RUNNING,
                ENTRY_SCAN_READY,
                ENTRY_DELETED,
                ENTRY_FAILED // IO Error or another error
} EntryState;

/* Entry is a single entry in a directory */
typedef struct {
        EntryState state;
        char *name;
        struct stat stat;
        char *link;
        int error;                          /* If there was a IO error with stat() */
        struct JobStruct *last_job;         /* Last queued job associated with this entry  */
        struct DirectoryStruct *dir;
} Entry;

/* We keep the fd of all directories around until the directories are processed to be able to use 
   openat() and to make sure that symlink or mv race conditions do not take us to a wrong directory */
typedef struct DirectoryStruct {
        int magick; /* 0xDADDAD to catch a race, 0xDEADBEEF to mark a zombie */
        int fd;
        atomic_int fdrefs; // Count references to fd so that we can cache fds
        struct stat stat;
        struct DirectoryStruct *parent;
        Entry *parent_entry;
        char *name;
        int entries;
        atomic_int descendants; /* Total number of known descendants, which grows while they are being scanned. */
        atomic_int ref;
        Entry *array;
        Entry **sorted;
        struct DirectoryStruct *lru_prev;
        struct DirectoryStruct *lru_next;
} Directory;

typedef struct {
        struct timespec start_clock_boottime;
        atomic_int dirs_read;
        atomic_int entries_checked;
        atomic_llong bytes_checked;
        int dirs_skipped;
        int files_skipped;
        atomic_int files_synced;

        atomic_int read_directory_jobs;
        atomic_int read_directory_miss;
    
        int pre_scan_hits;
        int pre_scan_wait_hits;
        int pre_scan_misses;
        int pre_scan_too_late; /* Prescan was too late, the directory was already scanned by another thread */
        int pre_scan_dirs;
        int pre_scan_allocated;
        int pre_scan_used;

        int jobs;
        int maxjobs;
        int queued;

        int dirs_active;
        int entries_active;
        int dirs_active_max;
        int dirs_freed;

        int slow_io_secs;
        int idle_threads;
        atomic_int open_dir_count;
} Scans;
extern Scans scans;
typedef struct JobStruct Job;
typedef enum {
        RET_OK=1,
        RET_NONE=0,
        RET_FAILED=-1,
        RET_RUNNING=-2
} JobResult;

typedef JobResult (JobCallback) (
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
#define strdup(X) ( use_my_strdup_instead(X) )


extern int progress;
extern int privacy;
extern int recursive;



// scandir.c
// submit_job() flags
#define DSYNC_FILE_WAIT -123 // Wait for all jobs to attached to From Entry to finish before starting job
#define DSYNC_DIR_WAIT  -124 // Wait for all jobs attached to to Directory to finish before starting job
Job *submit_job(Directory *from, Entry *source, Directory *to, const char *target, off_t offset, JobCallback *callback);
void job_lock();
void job_unlock();

Entry *directory_lookup(const Directory *d, const char *name);
Directory *scan_directory(Directory *parent, Entry *e);
void show_error(const char *why, const char *file);
Entry *init_entry(Entry * entry, int dfd, char *name);
Directory *pre_scan_directory(Directory *parent, Entry *dir);
void start_job_threads(int threads, Job *job);
void d_freedir(Directory *dir);
int wait_for_entry(Entry *job);
const char *dir_path(const Directory *d);
const char *file_path(const Directory *d, const char *f);
void show_error_dir(const char *message, const Directory *parent, const char *file);
JobResult run_one_job(Job *j);
JobResult run_any_job();
int print_jobs(FILE *f);
void set_thread_status_f(const char *file, const char *s, const char *func, int mark);
#define set_thread_status(file,s) set_thread_status_f(file, s, __func__, 0)
#define mark_job_start(file,s) set_thread_status_f(file, s, __func__, 1)
void print_progress();
int dir_open(Directory *d);
int dir_close(Directory *d);
int dir_openat(Directory *d, const char *f);
void d_freedir(Directory *dir);
void dir_claim(Directory *dir);


