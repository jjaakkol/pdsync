#include "dsync.h"

// This file contains Entry and Directory handling

// LRU cache for open directory file handles
#define MAX_OPEN_DIRS 1000

static Directory *lru_head = NULL;
static Directory *lru_tail = NULL;

typedef struct DentStruct {
        char *name;
        ino_t d_ino;
        unsigned char d_type;
} Dent;


void show_error_dir(const char *message, const Directory *parent, const char *file)
{
        fprintf(stderr, "Error: %s : %s : %s%s\n", message, strerror(errno), dir_path(parent), file);
}

static pthread_mutex_t lru_mut = PTHREAD_MUTEX_INITIALIZER;

// Add directory to LRU head
static void lru_add(Directory *d) {
    assert(d->fd>0);
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

/* Initialize a Entry when given a fd of open directory */
Entry *init_entry(Entry *entry, int dfd, char *name)
{
        memset(entry, 0, sizeof(*entry));
        entry->name = name;

        if (fstatat(dfd, name, &entry->stat, AT_SYMLINK_NOFOLLOW) < 0)
        {
                entry->error = errno;
                show_error("fstatat", name);
        }
        else if (S_ISLNK(entry->stat.st_mode))
        {
                /* Read the symlink if there is one. FIXME: maybe skip this if we don't have --preserve-links */
                char linkbuf[MAXLEN];
                int link_len;
                if ((link_len = readlinkat(dfd, name, linkbuf, sizeof(linkbuf) - 1)) <= 0)
                {
                        /* Failed to read link. */
                        show_error("readlink", name);
                        /* FIXME: read errors is not visible here:
                        opers.read_errors++; */
                }
                else
                {
                        /* Save the link */
                        entry->link = my_malloc(link_len + 1);
                        memcpy(entry->link, linkbuf, link_len);
                        entry->link[link_len] = 0;
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
                    d->parent->parent_entry->stat.st_uid != 0 && dir_stat(d)->st_uid != getuid())
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

/* Free a directory structure, including its finished jobs */
static void d_freedir_locked(Directory *dir)
{
        assert(dir->magick == 0xDADDAD);
        assert(dir->ref>=0);
        assert(dir->parent_entry && dir->parent_entry->dir==dir);

        atomic_fetch_add(&dir->ref, -1);
        if (dir->ref>0) return; 
        assert(dir->ref==0);
        assert(dir->fdrefs==0);

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
                if (e->link)
                        free(e->link);
                free(e->name);
        }
        free(dir->array);
        free(dir->sorted);

        dir->magick = 0xDADDEAD;

        free(dir->name);
        dir->entries = -123; /* Magic value to debug a race */
        dir->parent_entry->dir=NULL;
        if (dir->parent)
                d_freedir_locked(dir->parent);
        free(dir);
}

static int dir_close_locked(Directory *d) {
        assert(d->magick==0xDADDAD);
        assert(d->ref>0 && d->fdrefs>0);
        atomic_fetch_add(&d->fdrefs, -1);
        if (d->fdrefs==0) d_freedir_locked(d);
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
                        show_error_dir("dir_openat probably a fd leak BUG", parent, name);
                        abort();
                }
                show_error_dir("dir_openat", parent, name);
        }
        if (parent && pfd>=0) dir_close_locked(parent);
        return dfd;
}

/* gets a file handle to Directory, possibly reopening it */
static int dir_open_locked(Directory *d)
{
        assert(d->magick==0xDADDAD);
        assert(d->ref>0);

        if (d->fdrefs==0) atomic_fetch_add(&d->ref,1); /* We reference count claim a directory, which has a open fd claim */
        atomic_fetch_add(&d->fdrefs, 1);
        if (d->fd < 0)
        {
                // If too many open, close LRU
                while (atomic_load(&scans.open_dir_count) >= MAX_OPEN_DIRS) {
                        lru_close_one();
                }
                int fd = dir_openat_locked(d->parent, d->name);
                struct stat s;
                if (fd < 0 || fstat(fd, &s) < 0 ||
                        s.st_ino != dir_stat(d)->st_ino ||
                        s.st_dev != dir_stat(d)->st_dev)
                {
                        show_error_dir("Directory changed or unavailable", d, d->name);
                        return -1;
                }
                d->fd = fd;
                lru_add(d);
        } else {
                lru_move_to_head(d);
        }
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
        d_freedir_locked(dir);
        pthread_mutex_unlock(&lru_mut);
}       

static int entrycmp(const void *x, const void *y) {
        Entry **a = (Entry **)x;
        Entry **b = (Entry **)y;
        return strcmp((*a)->name, (*b)->name);
}

/* Directory read is split in two Jobs
 * - read_directory reads a directory and submits more directories to be read
 * - Doesn't stat the entries, because stats are slow and we wan't the job size quickly
 */
int read_directory(Directory *parent, Entry *parent_entry, Directory *not_used_d, const char *name, off_t depth)
{
        int allocated = 1024;
        int dfd = -1;
        DIR *d = NULL;
        struct stat tmp_stat;
        int entries = 0;
        Dent *dents = NULL;


        assert(!parent || parent->magick != 0xDADDEAD);
        assert(!parent || parent->magick == 0xDADDAD);
        assert(!parent || parent->ref>0);

        if (depth>0) atomic_fetch_add(&scans.read_directory_jobs, -1);

        job_lock();
        switch (parent_entry->state) {
                case ENTRY_CREATED:  // FIXME dsync() does not init parent_entry. It probably should
                case ENTRY_INIT: break;
                case ENTRY_READ_QUEUE: break;
                case ENTRY_READING: job_unlock(); return RET_RUNNING;  /* Some other thread is already reding it */
                case ENTRY_READ_READY: 
                case ENTRY_SCAN_QUEUE:
                case ENTRY_SCAN_RUNNING:
                case ENTRY_SCAN_READY:
                        goto out; // Already done 
                case ENTRY_FAILED: goto out;     // IO error happened. Don't retry.
                case ENTRY_DELETED: goto out;    // Deleted already
        }

        // This thread won the race and really reads the directory.
        // If it was called with depth=0 it was a pre read_directory miss
        if (depth==0) atomic_fetch_add(&scans.read_directory_miss,1);

        set_thread_status(file_path(parent,name),"readdir");
        Directory *nd=my_calloc(1, sizeof(Directory));
        parent_entry->dir=nd; // will be filled when we finish
        parent_entry->state=ENTRY_READING;
        job_unlock();

        if ((dfd = dir_openat(parent, name)) < 0 || (d = fdopendir(dfd)) == NULL || fstat(dfd, &tmp_stat) < 0)
        {
                parent_entry -> error=errno;
                parent_entry->state=ENTRY_FAILED;
                show_error_dir("open directory", parent, name);
                goto fail;
        }

        /* Read the directory and save the names and dents */
        dents = my_calloc(allocated, sizeof(*dents));
        errno = 0;
        struct dirent *dent;
        while ((dent = readdir(d)))
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
                parent_entry->error=errno;
                show_error_dir("readdir", parent, name);
                goto fail;
        }
        //dents = my_realloc(dents, sizeof(*dents) * entries); /* Waste less memory */

        /* Init the Directory structure */
        nd->parent = parent;
        nd->name = my_strdup(name);
        nd->parent_entry = parent_entry;
        nd->ref = 1; /* The directory is now referenced once */
        nd->magick = 0xDADDAD;
        nd->fd = -1;
        nd->entries=entries;
        nd->array = my_calloc(entries, sizeof(Entry));
        nd->sorted = my_calloc(entries, sizeof(Entry *));
        if (parent) dir_claim(parent); /* Parent is referenced by this dir */

        /* Init the entry array for Directories and submit jobs */
        for (int i = 0; i < entries; i++) {
                nd->array[i].name=dents[i].name;
                if (recursive && dents[i].d_type==DT_DIR) {
                        Entry *e=&nd->array[i];
                        init_entry(e, dfd, e->name);
                        //printf("submit job %s depth %ld\n",file_path(nd, e->name), depth+1);
                        if ( S_ISDIR(e->stat.st_mode) ) {
                                e->state=ENTRY_READ_QUEUE;
                                if (e->stat.st_nlink==2) {
                                        submit_job(nd, e, NULL, e->name, depth+1, read_directory);
                                        atomic_fetch_add(&scans.read_directory_jobs,1);
                                }
                        }
                }
        }
        free(dents);
        closedir(d);

        /* Now create the sorted array */
        for (int i=0; i<entries; i++) nd->sorted[i]=&nd->array[i];
        qsort(nd->sorted, entries, sizeof(Entry *), entrycmp);

        job_lock(); /* FIXME: maybe lru lock is enough */
        while (parent) {
                atomic_fetch_add(&parent->descendants, entries);
                parent=parent->parent;
        }
        parent_entry->state=ENTRY_READ_READY;

        /* Update stats */
        if (++scans.dirs_active > scans.dirs_active_max) scans.dirs_active_max = scans.dirs_active;
        scans.entries_active += entries;
        atomic_fetch_add(&scans.dirs_read, 1);
        //printf("readdir done %s %ld\n",file_path(parent,name),depth);

        out: 
        job_unlock();
        return RET_OK;

        fail:
        job_lock();
        if (dfd>=0) close(dfd);
        for(int i=0; i<entries; i++) free(dents[i].name);
        free(dents);
        parent_entry->state=ENTRY_FAILED;
        parent_entry->dir=NULL;
        free(nd);
        job_unlock();
        return RET_FAILED;
}

/* scan_directory can be called from multiple threads */
Directory *scan_directory(Directory *parent, Entry *entry)
{
        assert(!parent || parent->magick != 0xDADDEAD);
        assert(!parent || parent->magick == 0xDADDAD);

        //printf("scan directory %s\n", file_path(parent, entry->name)); 
        while(read_directory(parent, entry, NULL, entry->name, 0)==RET_RUNNING) {
                job_lock();
                if (entry->state==ENTRY_READING) run_any_job();
                job_unlock();
        }
        if (entry->state==ENTRY_FAILED) return NULL;

        Directory *nd=entry->dir;
        assert(entry->state==ENTRY_READ_READY);
        entry->state=ENTRY_SCAN_RUNNING;;
        assert(nd);
        set_thread_status(file_path(parent, entry->name), "scandir");

        if (dir_open(nd) < 0) {
                d_freedir(nd);
                return NULL;
        }

        /* Initialize ((stat) all the entries which have not been stated, in readdir() order */
        for (int i = 0; i < nd->entries; i++) {
                Entry *e = &nd->array[i];
                if (e->state==ENTRY_CREATED) init_entry(e, nd->fd, e->name);
        }

        set_thread_status(file_path(parent, entry->name), "scandir done");
        dir_close(nd);
        assert(nd->ref>0);
        return nd;
}


/*
 * FIXME rethink this
 * - If it isn't scanned yet we scan it in this thead or wait for it to be scanned
 * - If it is already done we return the result
 * - Otherwise we do the scan
 * - Launch scan jobs for subdirectories
 */
Directory *pre_scan_directory(Directory *parent, Entry *dir) {

        assert(dir);

        return scan_directory(parent,dir);
}
#if 0
{
        Directory *result = NULL;
        int i;
        Job *d = dir->job;
        if (dir->job && (dir->job->state==SCAN_WAITING || dir->job->state==SCAN_RUNNING || dir->job->state==SCAN_READY)) {
                /* We have a prescan job */
                switch (d->state) {
                case SCAN_WAITING:
                        /* The job for this directory has not started yet. Run it ourselves */
                        scans.pre_scan_misses++;
                        scans.pre_scan_hits++;
                        break;
                default: assert(0);
                }
                scans.pre_scan_used++;
                result = d->result;
                free_job(dir->job);
                assert(!dir->job || dir->job->magick == 0x10b10b);

                pthread_cond_broadcast(&cond); /* wake up anyone who was waiting for this */
        } else scans.pre_scan_misses++; // No prescan job was running. 

        if (!result) {
                set_thread_status(file_path(parent, dir->name), "scanning dir");
                /* The directory was not in queue. Scan it in this thread */
                pthread_mutex_unlock(&mut); /* Do not lock the critical section during IO or scan_directory */
                result = scan_directory(parent, dir);
                pthread_mutex_lock(&mut);
        }
        if (!result) {
                show_error_dir("Failed to scan a directory", parent, dir->name);
                goto out;
        }

        /* Now add the newly found directories to the job queue for pre scan */
        for (i = result->entries - 1; i >= 0; i--)
        {
                if (S_ISDIR(result->array[i].stat.st_mode))
                {
                        if (result->array[i].job)
                        {
                                scans.pre_scan_too_late++;
                                /* Already has a job, skip it */
                                continue;
                        }
                        Job *d = my_calloc(1, sizeof(*d));
                        d->magick = 0x10b10b;
                        d->fentry = &result->array[i];
                        result->array[i].job = d; /* Link the entry to the job */
                        d->from = result;
                        d->result = NULL;
                        d->state = SCAN_WAITING;
                        d->callback = NULL;
                        if (last_job) last_job->next=d;
                        else {
                                assert(pre_scan_list==NULL);
                                last_job=pre_scan_list=d;
                                d->next = pre_scan_list;
                        }
                        dir_claim(result); /* The directory is now referenced by the Job */
                        scans.pre_scan_allocated++;
                        scans.queued++;
                        scans.jobs++;
                        if (scans.queued > scans.maxjobs)
                                scans.maxjobs = scans.queued;
                }
        }
        dir->state=ENTRY_SCAN_READY;

out:
        pthread_cond_broadcast(&cond);
        pthread_mutex_unlock(&mut);

        assert(!result || result->ref>0);
        return result;
}
#endif

