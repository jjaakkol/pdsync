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

typedef enum
{
        ENTRY_CREATED,
        ENTRY_DIR,
        ENTRY_INIT,
//        ENTRY_READ_RUNNING,
//        ENTRY_READ_READY,
//        ENTRY_SCAN_RUNNING,
//        ENTRY_SCAN_READY,
        ENTRY_DELETED,
        ENTRY_FREED,
        ENTRY_FAILED // IO Error or another error
} EntryState;

/* Entry is a single entry in a directory */
typedef struct
{
        struct stat _stat;
        char *name;
        char *link;
        struct DirectoryStruct *dir; // Subdirectory if this is a directory
        EntryState state;
} Entry;

// We keep the fd's of directories in a LRU cache to avoid closing and opening needlessly
// We use openat() always to open files
typedef struct DirectoryStruct
{
        int magick;                       // 0xDADDAD to catch a race, 0xDEADBEEF to mark a zombie
        int fd;                           // fd of open directory, -1 if not open
        atomic_int fdrefs;                // Count references to fd so that we can cache fds
        struct DirectoryStruct *lru_prev; // The LRU list
        struct DirectoryStruct *lru_next;
        struct DirectoryStruct *parent;
        Entry *parent_entry;
        char *name;
        int entries;
        atomic_int descendants; // Total number of known descendants, which grows while they are being scanned. */
        atomic_int ref;
        Entry *array;
        Entry **sorted;
        struct JobStruct *last_job;
        int jobs; // Number of jobs running or queued in this directory
} Directory;

// Stats for things that are not counted as modifications
typedef struct
{
        struct timespec start_clock_boottime;
        atomic_int dirs_read;
        atomic_int entries_checked;
        atomic_llong bytes_checked;
        atomic_llong bytes_skipped;
        int dirs_skipped;
        int files_skipped;
        atomic_int files_synced;
        atomic_int hard_links_saved;

        atomic_int read_directory_jobs; // Jobs reading a Directory. If all dirs have been read this is 0
        int maxjobs;
        int queued;
        int jobs_waiting;      // Jobs waiting for other jobs to finish
        atomic_llong jobs_run; // Number of jobs already finished

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
typedef enum
{
        RET_OK = 1,
        RET_NONE = 0,
        RET_FAILED = -1,
        RET_RUNNING = -2
} JobResult;

typedef JobResult(JobCallback)(
    Directory *from,
    Entry *from_entry,
    Directory *to,
    const char *target,
    off_t offset);

/* It is a useless distraction to deal with out of memory. Just die. */
static inline char *my_strdup(const char *str)
{
        char *s = strdup(str);
        if (!s)
        {
                fprintf(stderr, "strdup() out of memory. Exiting with status 2.\n");
                exit(2);
        }
        return s;
}
static inline void *my_calloc(size_t nmemb, size_t size)
{
        void *ptr = calloc(nmemb, size);
        if (!ptr)
        {
                fprintf(stderr, "Out of memory. Exiting with status 2.\n");
                exit(2);
        }
        return ptr;
}
static inline void *my_malloc(size_t size)
{
        return my_calloc(1, size);
}
static inline void *my_realloc(void *ptr, size_t size)
{
        void *newptr = realloc(ptr, size);
        if (!newptr)
        {
                fprintf(stderr, "realloc() out of memory. Exiting with status 2.\n");
                exit(2);
        }
        return newptr;
}
#define strdup(X) (use_my_strdup_instead(X))

#define DEBUG(...)                                                                            \
        do                                                                                    \
        {                                                                                     \
                if (debug > 0)                                                                \
                {                                                                             \
                        fprintf(stderr, "[%-12s:%20s():%4d] ", __FILE__, __func__, __LINE__); \
                        fprintf(stderr, __VA_ARGS__);                                         \
                }                                                                             \
        } while (0)

// Interface to dsync.c
extern int progress;
extern int privacy;
extern int recursive;
extern int debug;
extern int threads;
extern FILE *tty_stream;

void show_error(const char *why, const char *file);
void show_error_dir(const char *message, Directory *parent, const char *file);
void set_thread_status_f(const char *file, const char *s, const char *func, int mark);
void print_progress();

// Interface to jobs.c
#define DSYNC_FILE_WAIT -123 // Wait for all jobs to attached to From Entry to finish before starting job
#define DSYNC_DIR_WAIT -124  // Wait for all jobs attached to to Directory to finish before starting job
#define set_thread_status(file, s) set_thread_status_f(file, s, __func__, 0)
#define mark_job_start(file, s) set_thread_status_f(file, s, __func__, 1)
#define submit_job(from, source, to, target, offset, callback)               \
        do                                                                   \
        {                                                                    \
                DEBUG("submit_job callback=%s\n", #callback);                \
                submit_job_real(from, source, to, target, offset, callback); \
        } while (0)

Job *submit_job_real(Directory *from, Entry *source, Directory *to, const char *target, off_t offset, JobCallback *callback);
void submit_or_run_job(Directory *from, Entry *source, Directory *to, const char *target, off_t offset, JobCallback *callback);
Job *submit_job_first(Directory *from, Entry *source, Directory *to, const char *target, off_t offset, JobCallback *callback);
void job_lock();
void job_unlock();
JobResult run_any_job();
void start_job_threads(int threads);
int print_jobs(FILE *f);

// Interface to directory.c
Entry *directory_lookup(const Directory *d, const char *name);
Directory *scan_directory(Directory *dir);
Directory *read_directory(Directory *parent, Entry *parent_entry);
Entry *init_entry(Entry *entry, int dfd, char *name);
void d_freedir(Directory *dir);
const char *dir_path(const Directory *d);
const char *file_path(const Directory *d, const char *f);
int dir_open(Directory *d);
int dir_close(Directory *d);
int dir_openat(Directory *d, const char *f);
void dir_claim(Directory *dir);
int file_stat(Directory *d, const char *name, struct stat *s);

static inline Entry *dir_entry(Directory *d, int i) {
        Entry *e=&d->array[i];
        return e;
}

static inline const struct stat *entry_stat(const Entry *e)
{
        assert(e);
        assert(e->state != ENTRY_CREATED && e->state != ENTRY_FAILED);
        return &e->_stat;
}
static inline const struct stat *dir_stat(const Directory *d)
{
        return entry_stat(d->parent_entry);
}
static inline int entry_isdir(Entry *e)
{
        assert(e);
        switch(e->state) {
        case ENTRY_DIR: return 1;
        case ENTRY_CREATED: return 0;
        case ENTRY_FAILED: return 0;
        default: break;
        }
        return S_ISDIR(entry_stat(e)->st_mode);
}
static inline int entry_isdir_i(Directory *d, int i)
{
        return entry_isdir(&d->array[i]);
}
