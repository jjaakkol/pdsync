#define _GNU_SOURCE
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/sysmacros.h>
#include <liburing.h>

#include "dsync.h"

// This file contains Entry and Directory handling

// LRU cache for open directory file handles
static int max_open_dirs=0;  // initialize this when first used

static Directory *lru_head = NULL;
static Directory *lru_tail = NULL;

typedef struct DentStruct {
        char *name;
        ino_t d_ino;
        unsigned char d_type;
} Dent;


void show_error_dir(const char *message, Directory *parent, const char *file)
{
        fprintf(stderr, "Error: %s : %s : %s%s\n", message, strerror(errno), dir_path(parent), file);
}

static pthread_mutex_t lru_mut = PTHREAD_MUTEX_INITIALIZER;

// Add directory to LRU head
static void lru_add(Directory *d) {
    assert(d->fd>=0);
    atomic_fetch_add(&scans.open_dir_count, 1);
    d->lru_prev = NULL;
    d->lru_next = lru_head;
    if (lru_head) lru_head->lru_prev = d;
    lru_head = d;
    if (!lru_tail) lru_tail = d;
}

// Move directory to LRU head
static void lru_move_to_head(Directory *d) {
    if (lru_head == d) return;
    // Remove from current position
    if (d->lru_prev) d->lru_prev->lru_next = d->lru_next;
    if (d->lru_next) d->lru_next->lru_prev = d->lru_prev;
    if (lru_tail == d) lru_tail = d->lru_prev;
    // Insert at head
    d->lru_prev = NULL;
    d->lru_next = lru_head;
    if (lru_head) lru_head->lru_prev = d;
    lru_head = d;
    if (!lru_tail) lru_tail = d;
}

// Remove directory from LRU list
static void lru_remove(Directory *d) {
        assert(d->fd>=0);
        close(d->fd);
        d->fd=-1;
        atomic_fetch_add(&scans.open_dir_count,-1);
        if (d->lru_prev) d->lru_prev->lru_next = d->lru_next;
        if (d->lru_next) d->lru_next->lru_prev = d->lru_prev;
        if (lru_head == d) lru_head = d->lru_next;
        if (lru_tail == d) lru_tail = d->lru_prev;
        d->lru_prev = d->lru_next = NULL;
}

// Remove LRU tail and close its fd
static void lru_close_one() {
        assert(lru_tail);
        Directory *old = lru_tail;
        while(old && old->fdrefs>0) {
                old=old->lru_prev;
        }
        assert(old);
        lru_remove(old);
        //printf("lru_close_one: tried %d, open %d\n",tried, open_dir_count);
}

// Helper function to fstatat a file. FIXME: clean code by using this more
int file_stat(Directory *d, const char *name, struct stat *s) {
        int dfd=dir_open(d);
        if (dfd<0) return -1;
        int ret=fstatat(dfd, name, s, AT_SYMLINK_NOFOLLOW);
        dir_close(d);
        return ret;
}

/* Initialize a Entry when given a fd of open directory */
Entry *init_entry(Entry *entry, int dfd, char *name)
{
        entry->name = name;

        if (fstatat(dfd, name, &entry->_stat, AT_SYMLINK_NOFOLLOW) < 0)
        {
                if (errno==ENOENT) {
                        // File was removed after readdir(), maybe by sync_remove()
                        // Ignore this, since if it was us it was intentional and if it was someone else it was intentional too.
                        entry->state = ENTRY_DELETED;
                } else {
                        show_error("fstatat", name);
                        entry->state = ENTRY_FAILED;
                }
        }

        atomic_fetch_add(&scans.entries_checked, 1);
        entry->state=ENTRY_INIT;
        return entry;
}

const char *dir_path(const Directory *d)
{
        _Thread_local static char buf[MAXLEN];
        _Thread_local static int len;
        if (d)
        {
                assert(d->magick==0xDADDAD);
                dir_path(d->parent);
                if (privacy && d->parent && d->parent->parent_entry &&
                    entry_stat(d->parent->parent_entry)->st_uid != 0 && dir_stat(d)->st_uid != getuid())
                {
                        len += snprintf(buf + len, MAXLEN - len, "[0x%lx]/", dir_stat(d)->st_ino);
                }
                else
                {
                        len += snprintf(buf + len, MAXLEN - len, "%s/", d->name);
                }
        }
        else
                len = snprintf(buf, MAXLEN, "%s", "");
        return buf;
}

const char *file_path(const Directory *d, const char *f)
{
        _Thread_local static char buf[MAXLEN];
        if (privacy && d && d->parent_entry && dir_stat(d)->st_uid != 0 && dir_stat(d)->st_uid != getuid())
        {
                snprintf(buf, sizeof(buf), "%s%s", dir_path(d), "[PRIVACY]");
        }
        else
        {
                snprintf(buf, sizeof(buf), "%s%s", dir_path(d), f);
        }
        return buf;
}

// Free a directory structure if refcount goes zero. Directory mutex must be held.
static void dir_freedir_locked(Directory *dir)
{
        assert(dir->magick == 0xDADDAD);
        assert(dir->ref>=0);
        assert(dir->parent_entry);
        assert(!dir->parent_entry->dir || dir->parent_entry->dir==dir);

        atomic_fetch_add(&dir->ref, -1);
        DEBUG("refcount %s %d\n", dir_path(dir), dir->ref);

        if (dir->ref>0) return;
        assert(dir->ref==0);
        assert(dir->fdrefs==0);
        assert(dir->last_job==NULL);

        if (dir->fd >= 0) {
                lru_remove(dir);
        }

        scans.dirs_active--;
        scans.entries_active -= dir->entries;
        scans.dirs_freed++;

        while (dir->entries > 0)
        {
                dir->entries--;
                Entry *e = &dir->array[dir->entries];
                free(e->name);
        }
        free(dir->array);
        free(dir->sorted);

        dir->magick = 0xDADDEAD;

        free(dir->name);
        dir->entries = -123; /* Magic value to debug a race */
        dir->parent_entry->dir=NULL;
        dir->parent_entry->state=ENTRY_FREED;
        if (dir->parent)
                dir_freedir_locked(dir->parent);
        free(dir);
}

static int dir_close_locked(Directory *d) {
        assert(d->magick==0xDADDAD);
        assert(d->ref>0 && d->fdrefs>0);
        atomic_fetch_add(&d->fdrefs, -1);
        if (d->fdrefs==0) dir_freedir_locked(d);
        return 0;
}

static int dir_open_locked(Directory *d);

/* Opens a file or directory, hopefully safely  */
static int dir_openat_locked(Directory *parent, const char *name)
{
        assert(!parent || parent->magick==0xDADDAD);
        int pfd = (parent) ? dir_open_locked(parent) : AT_FDCWD;
        int dfd = openat(pfd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NOATIME);
        if (dfd < 0 && errno == EPERM)
                dfd = openat(pfd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW); // Try again without O_NOATIME
        if (dfd < 0) {
                if (errno==EMFILE) {
                        show_error_dir("dir_openat: probably a fd leak BUG", parent, name);
                        abort();
                }
                // show_error_dir("dir_openat", parent, name); // Caller shows error message
        }
        if (parent && pfd>=0) dir_close_locked(parent);
        return dfd;
}

// gets a file handle to Directory, possibly reopening it
// Keeps reference counts the fd and the dir
static int dir_open_locked(Directory *d)
{
        assert(d->magick==0xDADDAD);
        assert(d->ref>0);


        // init max_open_dirs if not init yet
        if (max_open_dirs==0) {
                struct rlimit rl;
                if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
                        // Every thread requires at least 2 fd's when copying files
                        max_open_dirs = rl.rlim_cur - 4*threads - 16;
                } else {
                        // How can this fail?
                        fprintf(stderr, "getrlimit(RLIMIT_NOFILE) failed: %s", strerror(errno));
                        exit(1);
                }
                if (max_open_dirs<threads*2+16) {
                        fprintf(stderr,"Error: Max nummber of open files RLIMIT_NOFILE too low (%ld). Use ulimit -n to increase. Exiting.\n", rl.rlim_cur);
                        exit(1);
                }
                DEBUG("Using max_open_dirs=%d\n", max_open_dirs);
        }

        // Open the directory if not already open
        if (d->fd < 0)
        {
                // If too many open, close LRU
                while (atomic_load(&scans.open_dir_count) >= max_open_dirs) {
                        lru_close_one();
                }
                int fd = dir_openat_locked(d->parent, d->name);
                if (fd<0) {
                        show_error_dir("open() directory", d, ".");
                        return -1;
                }
                struct stat s;
                if (fstat(fd, &s) < 0 ) {
                        show_error_dir("fstat() direcotry", d, ".");
                        close(fd);
                        return -1;
                }
                if (dir_stat(d)->st_ino==0 && dir_stat(d)->st_dev==0) {
                        // First time open, save stat info
                        d->parent_entry->_stat=s;
                } else if (dir_stat(d)->st_ino != s.st_ino || dir_stat(d)->st_dev != s.st_dev) {
                        // Directory has changed under us!
                        show_error_dir("Directory inode or dev changed", d, ".");
                        close(fd);
                        return -1;
                }
                d->fd = fd;
                lru_add(d);
        } else {
                // Move to LRU head since dir was use
                lru_move_to_head(d);
        }
        if (d->fdrefs==0) atomic_fetch_add(&d->ref,1);
        atomic_fetch_add(&d->fdrefs, 1);
        return d->fd;
}


int dir_open(Directory *d)
{
        if (d==NULL) return AT_FDCWD; // hack
        pthread_mutex_lock(&lru_mut);
        int fd = dir_open_locked(d);
        pthread_mutex_unlock(&lru_mut);
        return fd;
}

int dir_close(Directory *d) {
        if (d==NULL) return 0;
        pthread_mutex_lock(&lru_mut);
        dir_close_locked(d);
        pthread_mutex_unlock(&lru_mut);
        return 0;
}

int dir_openat(Directory *parent, const char *name) {
        pthread_mutex_lock(&lru_mut);
        int dfd=dir_openat_locked(parent, name);
        pthread_mutex_unlock(&lru_mut);
        return dfd;
}

void dir_claim(Directory *d) {
        assert(d->magick==0xDADDAD);
        assert(d->ref>0);
        pthread_mutex_lock(&lru_mut);
        atomic_fetch_add(&d->ref, 1);
        pthread_mutex_unlock(&lru_mut);
}

void d_freedir(Directory *dir)
{
        pthread_mutex_lock(&lru_mut);
        dir_freedir_locked(dir);
        pthread_mutex_unlock(&lru_mut);
}

Entry *directory_lookup(const Directory *d, const char *name) {
        assert(d && name && d->sorted);

        int left = 0;
        int right = d->entries - 1;
        while (left <= right) {
                int mid = left + (right - left) / 2;
                int cmp = strcmp(d->sorted[mid]->name, name);
                if (cmp == 0) {
                        return d->sorted[mid];
                } else if (cmp < 0) {
                        left = mid + 1;
                } else {
                        right = mid - 1;
                }
        }
        return NULL;
}

static int entrycmp(const void *x, const void *y) {
        Entry **a = (Entry **)x;
        Entry **b = (Entry **)y;
        return strcmp((*a)->name, (*b)->name);
}

/* Directory read is split in two parts
 * - read_directory reads the directory entries and is fast
 * - Doesn't stat the entries, because stats are slow and we wan't stats of job size quickly
 */
Directory *read_directory(Directory *parent, Entry *parent_entry) {
        int allocated = 1024;
        int dfd = -1;
        DIR *d = NULL;
        int entries = 0;
        Dent *dents = NULL;
        Directory *nd=NULL;
        const char *name=parent_entry->name;

        set_thread_status(file_path(parent, name), "readdir");

        assert(!parent || parent->magick != 0xDADDEAD);
        assert(!parent || parent->magick == 0xDADDAD);
        assert(!parent || parent->ref>0);

        // Open the directory and save its fstat() while we have the chance
        if ((dfd = dir_openat(parent, name)) < 0 ||
                (d = fdopendir(dfd)) == NULL ||
                fstat(dfd, &parent_entry->_stat) < 0)
        {
                parent_entry->state=ENTRY_FAILED;
                show_error_dir("open directory", parent, name);
                goto fail;
        }
        parent_entry->state=ENTRY_INIT;

        /* Read the directory and save the names and dents */
        dents = my_calloc(allocated, sizeof(*dents));
        errno = 0;
        for (struct dirent *dent=NULL; (dent = readdir(d)) != NULL;)
        {
                if (dent->d_name[0] == '.')
                {
                        /* Skip '.' and '..' */
                        if (dent->d_name[1] == 0)
                                continue;
                        if (dent->d_name[1] == '.' && dent->d_name[2] == 0)
                                continue;
                }
                if (entries == allocated)
                {
                        allocated += allocated / 2;
                        dents = my_realloc(dents, sizeof(*dents) * allocated);
                }
                dents[entries].name = my_strdup(dent->d_name);
                dents[entries].d_ino = dent->d_ino;
                dents[entries].d_type = dent->d_type;
                entries++;
        }
        if (errno)
        {
                show_error_dir("readdir", parent, name);
                goto fail;
        }

        /* Init the Directory structure */
        nd=my_calloc(1, sizeof(Directory));
        parent_entry->dir=nd;
        nd->parent = parent;
        nd->name = my_strdup(name);
        nd->parent_entry = parent_entry;
        nd->ref = 1;                                    // Caller claims one reference by default
        nd->magick = 0xDADDAD;
        nd->fd = -1;
        nd->entries=entries;
        nd->array = my_calloc(entries, sizeof(Entry));
        nd->sorted = my_calloc(entries, sizeof(Entry *));
        if (parent) dir_claim(parent);                  // Parent is referenced by this dir */

        // Init the entry array for Directories
        for (int i = 0; i < entries; i++) {
                nd->array[i].name=dents[i].name;
                if (dents[i].d_type == DT_DIR) {
                        nd->array[i].state = ENTRY_DIR;
                }
        }
        free(dents);
        closedir(d);

        /* Now create the sorted array */
        for (int i=0; i<entries; i++) nd->sorted[i]=&nd->array[i];
        qsort(nd->sorted, entries, sizeof(Entry *), entrycmp);

        while (parent) {
                atomic_fetch_add(&parent->descendants, entries);
                parent=parent->parent;
        }

        /* Update stats */
        if (++scans.dirs_active > scans.dirs_active_max) scans.dirs_active_max = scans.dirs_active;
        scans.entries_active += entries;
        atomic_fetch_add(&scans.dirs_read, 1);
        //printf("readdir done %s %ld\n",file_path(parent,name),depth);
        assert(parent_entry->dir==nd);
        return nd;

        fail:
        if (dfd>=0) close(dfd);
        for(int i=0; i<entries; i++) free(dents[i].name);
        free(dents);
        parent_entry->state=ENTRY_FAILED;
        parent_entry->dir=NULL;
        free(nd);
        return NULL;
}

// Stat all entries in paraller using MAX_IN_FLIGHT size io_uring 
Directory *dir_stat_uring(Directory *nd) {
        const int MAX_IN_FLIGHT = 32;
        struct {
                int idx;
                struct statx statxbuf;
        } statx_jobs[MAX_IN_FLIGHT];
        int entries = nd->entries;
        struct io_uring ring;

        set_thread_status(dir_path(nd), "io_uring statx");

        int ret = io_uring_queue_init(entries > MAX_IN_FLIGHT ? MAX_IN_FLIGHT : entries, &ring, 0);
        if (ret < 0) {
                errno=ret;
                show_error_dir("io_uring_queue_init", nd, ".");
                dir_close(nd);
                return NULL;
        }

        // Single loop: submit jobs until MAX_IN_FLIGHT in flight, then collect completions and submit new jobs as slots free up
        int in_flight = 0;
        int next_entry = 0;
        int completed = 0;
        int job=0;
        while (completed < entries) {
                // Submit jobs while we have slots and entries left
                for (;in_flight < MAX_IN_FLIGHT && next_entry < entries; next_entry++) {
                        Entry *e = &nd->array[next_entry];
                        if (e->state > ENTRY_INIT) {
                                completed++; // Already done
                                continue;
                        }
                        struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
                        if (!sqe) {
                                show_error_dir("io_uring_get_sqe", nd, e->name);
                                exit(3); // How can this happen anyway?
                                continue;
                        }
                        statx_jobs[job].idx = next_entry;
                        io_uring_prep_statx(sqe, nd->fd, e->name, AT_SYMLINK_NOFOLLOW, STATX_BASIC_STATS, &statx_jobs[job].statxbuf);
                        io_uring_sqe_set_data64(sqe, job);
                        in_flight++;
                        job++;
                }
                if (in_flight > 0) 

                // Submit ring and wait for completions
                if (in_flight > 0) {
                        struct io_uring_cqe *cqe;
                        io_uring_submit(&ring);
                        int rc = io_uring_wait_cqe(&ring, &cqe);
                        if (rc < 0) break;
                        job = cqe->user_data; // Trick: the previous loop uses this job index
                        int idx = statx_jobs[job].idx;
                        Entry *e = &nd->array[idx];
                        struct statx *statxbuf = &statx_jobs[job].statxbuf;
                        if (cqe->res == 0 && statxbuf) {
                                // Fill e->_stat from statxbuf (basic fields)
                                e->_stat.st_mode = statxbuf->stx_mode;
                                e->_stat.st_ino = statxbuf->stx_ino;
                                e->_stat.st_nlink = statxbuf->stx_nlink;
                                e->_stat.st_uid = statxbuf->stx_uid;
                                e->_stat.st_gid = statxbuf->stx_gid;
                                e->_stat.st_size = statxbuf->stx_size;
                                e->_stat.st_dev = makedev(statxbuf->stx_dev_major, statxbuf->stx_dev_minor);
                                e->_stat.st_rdev = makedev(statxbuf->stx_rdev_major, statxbuf->stx_rdev_minor);
                                e->_stat.st_blksize = statxbuf->stx_blksize;
                                e->_stat.st_blocks = statxbuf->stx_blocks;
                                e->_stat.st_mtim.tv_sec = statxbuf->stx_mtime.tv_sec;
                                e->_stat.st_mtim.tv_nsec = statxbuf->stx_mtime.tv_nsec;
                                e->_stat.st_atim.tv_sec = statxbuf->stx_atime.tv_sec;
                                e->_stat.st_atim.tv_nsec = statxbuf->stx_atime.tv_nsec;
                                e->_stat.st_ctim.tv_sec = statxbuf->stx_ctime.tv_sec;
                                e->_stat.st_ctim.tv_nsec = statxbuf->stx_ctime.tv_nsec;
                                e->state = ENTRY_INIT;
                        } else if (cqe->res == -ENOENT) {
                                // File was removed after readdir(), maybe by sync_remove()
                                // Ignore this, since if it was us it was intentional and if it was someone else it was intentional too.
                                e->state = ENTRY_DELETED;
                        } else {
                                e->state = ENTRY_FAILED;
                                errno=-cqe->res;
                                show_error_dir("statx (io_uring)", nd, e->name);
                        }
                        io_uring_cqe_seen(&ring, cqe);
                        completed++;
                        in_flight--;
                }
        }
        io_uring_queue_exit(&ring);
        set_thread_status(dir_path(nd), "io_uring done");
        return nd;
}

Directory *scan_directory(Directory *nd) {
        assert(nd && nd->magick == 0xDADDAD);

        if (nd->parent_entry->state==ENTRY_FAILED) return NULL;
        if (nd->entries==0) return nd; // Empty directory, nothing to do

        if (dir_open(nd)<0) {
                show_error_dir("stat() files", nd, ".");
                return NULL;
        }

        if (use_io_uring) {
                Directory *ret=dir_stat_uring(nd);
                dir_close(nd);
                return ret;
        } else {
                // Initialize with fstatat() all the entries which have not been stated, in readdir() order
                set_thread_status(dir_path(nd), "stat files");
                for (int i = 0; i < nd->entries; i++) {
                        Entry *e = &nd->array[i];
                        if (e->state<=ENTRY_INIT) init_entry(e, nd->fd, e->name);
                }
        }

        set_thread_status(dir_path(nd), "stat done");
        dir_close(nd);
        assert(nd->ref>0);
        return nd;
}

