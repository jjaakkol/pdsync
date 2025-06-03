#include "dsync.h"

typedef enum
{
        SCAN_WAITING,
        SCAN_RUNNING,
        SCAN_READY,
        JOB_WAITING,
        JOB_RUNNING,
        JOB_READY,
        JOB_INVALID /* Catch use after frees */
} JobState;

typedef struct JobStruct
{
        pthread_t tid;
        int ret;
        Directory *to;
        int magick; /* 0x10b10b */
        Directory *from;
        Entry *fentry;
        const char *target;
        Directory *result;
        JobState state;
        struct JobStruct *next;
        JobCallback *callback;
        off_t offset;
} Job;

pthread_mutex_t mut = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
Job *pre_scan_list = NULL;

const char *dir_path(const Directory *d)
{
        _Thread_local static char buf[MAXLEN];
        _Thread_local static int len;
        if (d)
        {
                dir_path(d->parent);
                if (privacy && d->parent && d->parent->parent_entry &&
                    d->parent->parent_entry->stat.st_uid != 0 && d->stat.st_uid != getuid())
                {
                        len += snprintf(buf + len, MAXLEN - len, "[0x%lx]/", d->stat.st_ino);
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
        if (privacy && d && d->parent_entry && d->stat.st_uid != 0 && d->stat.st_uid != getuid())
        {
                snprintf(buf, sizeof(buf), "%s%s", dir_path(d), "[PRIVACY]");
        }
        else
        {
                snprintf(buf, sizeof(buf), "%s%s", dir_path(d), f);
        }
        return buf;
}

void show_error_dir(const char *message, const Directory *parent, const char *file)
{
        fprintf(stderr, "Error: %s : %s : %s%s\n", message, strerror(errno), dir_path(parent), file);
}

/* gets a file handle to Directory, possibly reopening it */
int dir_getfd_unlocked(Directory *d)
{
        if (d->fd < 0)
        {
                int fd = dir_openat(d->parent, d->name);
                struct stat s;
                if (fd < 0 || fstat(fd, &s) < 0 ||
                    s.st_ino != d->stat.st_ino ||
                    s.st_dev != d->stat.st_dev)
                {
                        show_error_dir("Directory changed or unavailable", d, d->name);
                        if (fd >= 0) close(fd);
                        fd=-1;
                }
                d->fd = fd;
        }
        return d->fd;
}

/* Opens a file or directory, hopefully safely  */
int dir_openat(Directory *parent, const char *name)
{
        int pfd = (parent) ? dir_getfd_unlocked(parent) : AT_FDCWD;
        int dfd = openat(pfd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NOATIME);
        if (dfd < 0 && errno == EPERM)
                dfd = openat(pfd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (dfd < 0) {
                if (errno==EMFILE) {
                        show_error_dir("dir_openat probably a fd leak BUG", parent, name);
                        abort();
                }
                show_error_dir("dir_openat", parent, name);
        }
        return dfd;
}

int dir_getfd(Directory *d)
{
        pthread_mutex_lock(&mut); // TODO: this mutex should be in Directory, not global
        d->fd = dir_getfd_unlocked(d);
        pthread_mutex_unlock(&mut);
        return d->fd;
}

/* Free a directory structure, including its finished jobs */
void d_freedir_locked(Directory *dir)
{
        assert(dir->magick == 0xDADDAD);

        dir->refs--;
        if (dir->refs > 0)
        {
                return;
        }
        scans.dirs_active--;
        scans.entries_active -= dir->entries;
        scans.dirs_freed++;

        while (dir->entries > 0)
        {
                dir->entries--;
                Entry *e = &dir->array[dir->entries];
                assert(!e->job); // no job should be running on this entry
                if (e->link)
                        free(e->link);
        }
        free(dir->array);
        free(dir->dents);

        dir->magick = 0xDADDEAD;
        if (dir->fd >= 0)
                close(dir->fd);

        free(dir->name);
        dir->entries = -123; /* Magic value to debug a race */
        if (dir->parent)
                d_freedir_locked(dir->parent);
        free(dir);
}

void d_freedir(Directory *dir)
{
        pthread_mutex_lock(&mut);
        d_freedir_locked(dir);
        pthread_mutex_unlock(&mut);
}

/* Remove job from queue's and free its resources. Mutex must be held. */
int free_job(Job *job)
{
        assert(job);
        assert(job->fentry);
        assert(job->state == JOB_READY || job->state == SCAN_READY);
        assert(job->magick == 0x10b10b);

        /* If Job happens to be fentry queue first, update the fentry queue */
        if (job->fentry->job == job)
        {
                if (job->next && job->fentry == job->next->fentry)
                {
                        // printf("Job %p fentry queue updated %p\n", job, job->fentry);
                        job->fentry->job = job->next;
                }
                else
                {
                        // printf("Job %p fentry queue clear %p. Next fentry queue %p\n", job, job->fentry, (job->next) ? job->next->fentry : NULL );
                        job->fentry->job = NULL;
                }
        }

        /* Remove job from pre_scan_list Job queue */
        if (pre_scan_list == job)
                pre_scan_list = job->next;
        else
        {
                Job *prev = pre_scan_list;
                assert(prev->magick == 0x10b10b);
                while (prev->next != job)
                        prev = prev->next;
                assert(prev); // the job must be in the list
                prev->next = job->next;
        }

        /* Freedir counts references */
        if (job->from)
                d_freedir_locked(job->from);
        if (job->to)
                d_freedir_locked(job->to);
        int ret = job->ret;
        job->next = NULL;
        job->state = JOB_INVALID;
        job->magick = 1234569; /* Mark as a zombie */
        free(job);

        return ret;
}

/* Initialize a directory Entry. */
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
        scans.entries_scanned++;
        entry->state=ENTRY_INIT;
        return entry;
}

static int entrycmp(const void *x, const void *y) {
        const Entry *a = (Entry *)x;
        const Entry *b = (Entry *)y;
        return strcmp(a->name, b->name);
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
        Directory *nd=NULL;

        assert(!parent || parent->magick != 0xDADDEAD);
        assert(!parent || parent->magick == 0xDADDAD);

        pthread_mutex_lock(&mut);
        if (parent_entry->dir) {
                // Another thread beat us. Run a job if not ready yet. 
                while(parent_entry->state!=ENTRY_READY) run_any_job();
                nd=parent_entry->dir; 
                goto out;
        }
        nd = my_calloc(1, sizeof(Directory));
        parent_entry->dir=nd; // will be filled when we finish
        pthread_mutex_unlock(&mut);

        //set_thread_status(file_path(parent, name), "readdir");
        if ((dfd = dir_openat(parent, name)) < 0 || (d = fdopendir(dfd)) == NULL || fstat(dfd, &tmp_stat) < 0)
        {
                show_error_dir("read_directory", parent, name);
                if (dfd >= 0) close(dfd);
                goto out;
        }

        /* Read the directory and save the names and dents */
        struct dirent *dents = my_calloc(allocated, sizeof(struct dirent));
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
                        dents = my_realloc(dents, sizeof(struct dirent) * allocated);
                }
                dents[entries] = *dent;
                entries++;
        }
        if (errno)
        {
                show_error_dir("readdir", parent, name);
                free(dents);
        }

        /* Obtain a lock to stop our own children from messing with us before we are ready */
        pthread_mutex_lock(&mut);

        /* Init the Directory structure */
        nd->parent = parent;
        nd->name = my_strdup(name);
        nd->parent_entry = parent_entry;
        nd->refs = 1; /* The directory is now referenced once */
        memcpy(&nd->stat, &tmp_stat, sizeof(tmp_stat));
        nd->dents = dents;
        nd->magick = 0xDADDAD;
        nd->fd = -1;
        nd->array = my_calloc(entries, sizeof(Entry));
        nd->entries=entries;

        for (int i = 0; i < entries; i++) {
                nd->array[i].name=my_strdup(nd->dents[i].d_name);
        }

        /* The entries need to be sorted alphabetically */
        qsort(nd->array, entries, sizeof(nd->array[0]), entrycmp);
        for (int i=1; i<nd->entries; i++) assert(strcmp(nd->array[i-1].name,nd->array[i].name)<=0);

        /* Init the entry array for Directories and submit jobs */
        for (int i = 0; recursive && i < entries; i++) {
                if (nd->dents[i].d_type==DT_DIR) {
                        Entry *e=directory_lookup(nd,nd->dents[i].d_name);
                        assert(e);
                        init_entry(e, dfd, e->name);
                        e->state=ENTRY_WAITING;
                        //printf("submit job %s depth %ld\n",file_path(nd, e->name), depth+1);
                        if ( S_ISDIR(e->stat.st_mode) ) {
                                submit_job_locked(nd, e, NULL, e->name, depth+1, read_directory);
                        } else {
                                // FIXME: do we need to handle a case like this?
                                show_error_dir("read_directory inode changed. Exiting.", parent, e->name);
                                exit(1);
                        }
                }
        }
        closedir(d);

        while (parent) {
                parent->descendants += entries;
                parent=parent->parent;
        }
        parent_entry->state=ENTRY_READY;
        //printf("readdir done %s %ld\n",file_path(parent,name),depth);

        out: 
        pthread_mutex_unlock(&mut);
        return 0;
}

/* scan_directory can be called from multiple threads */
Directory *scan_directory(Directory *parent, Entry *entry)
{
        assert(!parent || parent->magick != 0xDADDEAD);
        assert(!parent || parent->magick == 0xDADDAD);

        //printf("scan directory %s\n", file_path(parent, entry->name)); 
        read_directory(parent, entry, NULL, entry->name, 0);

        Directory *nd=entry->dir;
        assert(nd); // FIXME: can be NULL on directory read failure
        if (dir_getfd(nd) < 0) {
                d_freedir(nd);
                return NULL;
        }

        /* Initialize ((stat) all the entries which have not been stated, in readdir() order */
        for (int i = 0; i < nd->entries; i++) {
                char *name=nd->dents[i].d_name;
                mark_job_start(file_path(nd, name), "fstatat");
                Entry *e=directory_lookup(nd, name);
                assert(e);
                if (!e->dir) init_entry(e, nd->fd, name);
        }

        set_thread_status(file_path(parent, entry->name), "scandir done");

        return nd;
}

/* Threaded directory scan:
 * - if we know nothing of the directory scan it in this thread
 * - If it is already waiting in queue scan it in this thread.
 * - If it is already being scanned by another thread, wait for it.
 * - If it has been already scanned by another thread use the result.
 * - Launch directory scan jobs for subdirectories found.
 */
Directory *pre_scan_directory(Directory *parent, Entry *dir)
{
        Directory *result = NULL;
        int i;

        /* Mutex to handle jobs */
        pthread_mutex_lock(&mut);

        assert(dir);
        assert(!dir->job || dir->job->magick == 0x10b10b);

        Job *d = dir->job;
        if (dir->job && (dir->job->state==SCAN_WAITING || dir->job->state==SCAN_RUNNING || dir->job->state==SCAN_READY)) {
                /* We have a prescan job */
                switch (d->state) {
                case SCAN_WAITING:
                        /* The job for this directory has not started yet. We run it in this thread later */
                        scans.queued--;
                        scans.pre_scan_misses++;
                        d->state = SCAN_READY;
                        break;
                case SCAN_RUNNING:
                        /* Scan had already started. Wait for the scanning thread to finish */
                        scans.pre_scan_wait_hits++;
                        while (d->state != SCAN_READY)
                        {
                                run_any_job(); /* Run any job while waiting */
                        }
                        break;
                case SCAN_READY:
                        /* The scan has finished */
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

        /* Reopen the fd of prescanned directories.  */
        if (result) {
                assert(result->parent && result->parent->magick == 0xDADDAD);
                dir_getfd_unlocked(result);
                if (result->fd < 0) {
                        d_freedir(result);
                        goto out;
                }
        }
        else
        {
                set_thread_status(file_path(parent, dir->name), "scanning dir");
                /* The directory was not in queue or was not started. Scan it in this thread */
                pthread_mutex_unlock(&mut); /* Do not lock the critical section during IO or scan_directory */
                result = scan_directory(parent, dir);
                pthread_mutex_lock(&mut);
        }

        if (result == NULL)
                goto out;
        if (result->parent)
                result->parent->refs++;

        /* Lots of stats gathered */
        scans.dirs_scanned++;
        if (++scans.dirs_active > scans.dirs_active_max)
                scans.dirs_active_max = scans.dirs_active;
        scans.entries_active += result->entries;

        /* Now add the newly found directories to the job queue for pre scan */
        for (i = result->entries - 1; 0 && i >= 0; i--)
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
                        d->next = pre_scan_list;
                        pre_scan_list = d;
                        result->refs++; /* The directory is now referenced by the job */
                        scans.pre_scan_allocated++;
                        scans.queued++;
                        scans.jobs++;
                        if (scans.queued > scans.maxjobs)
                                scans.maxjobs = scans.queued;
                }
        }

out:
        pthread_cond_broadcast(&cond);
        pthread_mutex_unlock(&mut);

        return result;
}

/* Runs one job: can be called by a thread when waiting jobs to finish.
 * Assumes mutex is held.
 */
int run_one_job(Job *j)
{
        assert(j && j->magick == 0x10b10b);

        switch (j->state)
        {

        case SCAN_WAITING:
                j->state = SCAN_RUNNING;
                j->tid = pthread_self();
                mark_job_start(file_path(j->from, j->fentry->name), "readdir start");
                pthread_mutex_unlock(&mut);
                j->result = scan_directory(j->from, j->fentry);
                /* Don't keep prescanned directories open to conserve filedescriptos */
                if (j->result && j->result->fd >= 0)
                {
                        printf("Closing fd\n");
                        close(j->result->fd);
                        j->result->fd = -1;
                }
                pthread_mutex_lock(&mut);
                set_thread_status(file_path(j->from, j->fentry->name), "scanned dir");
                j->state = SCAN_READY;
                scans.queued--;
                pthread_cond_broadcast(&cond);
                return 1;

        case JOB_WAITING:
                assert(j->magick == 0x10b10b);
                j->state = JOB_RUNNING;
                assert(j->fentry);
                j->tid = pthread_self();
                mark_job_start(file_path(j->from, j->fentry->name), "job start");
                pthread_mutex_unlock(&mut);
                j->ret = j->callback(j->from, j->fentry, j->to, j->target, j->offset);
                pthread_mutex_lock(&mut);
                j->state = JOB_READY;
                scans.queued--;
                Job *wj = j->fentry->wait_queue;
                if (wj == NULL && j->from)  wj = j->from->parent_entry->wait_queue;
                free_job(j); /* If we ever need a mechanism to wait for job status, we could keep the job as a zombie job */
                if (wj)
                {
                        // Schedule the wait queue job, if there was one */
                        assert(wj->offset == DSYNC_FILE_WAIT || wj->offset == DSYNC_DIR_WAIT);
                        Job *i;
                        // Find if there are any jobs to be waited left
                        for (i = pre_scan_list; i; i = i->next)
                        {
                                if (i->fentry == wj->fentry)
                                        break;
                                if (wj->offset == DSYNC_DIR_WAIT && i->from && i->from->parent_entry == wj->fentry)
                                        break;
                        }
                        if (i == NULL)
                        {
                                // Schedule the job that was waiting
                                wj->next = pre_scan_list;
                                pre_scan_list = wj;
                                wj->fentry->wait_queue = NULL;
                        }
                        // printf("jobs left %d/%d in %s\n",jobs_left,scans.queued, file_path(wj->from, wj->fentry->name));
                }
                pthread_cond_broadcast(&cond);
                return 1;

        default:
                return 0;
        }
        return 0;
}

/* This is called:
 * - by the job queue thread to run jobs
 * - when threads are waiting for another thread to finish a job
 * This is called with the lock held.
 * This is where we would apply a scheduling policy, if there was one.
 */
int run_any_job()
{
        Job *j;
        // Run prescan jobs first, since someone is likely waiting for them
        for (j = pre_scan_list; j && (j->state != SCAN_WAITING); j = j->next)
                ;
        if (j && run_one_job(j))
                return 1; /* one SCAN job was run, return */
        for (j = pre_scan_list; j; j = j->next)
        {
                if (j->state == JOB_WAITING)
                        break; /* run the job */
        }
        if (j && run_one_job(j))
                return 1; /* one job was run, return */

        /* No jobs to run, we wait */
        mark_job_start(NULL, "idle");
        scans.idle_threads++;
        pthread_cond_wait(&cond, &mut);
        scans.idle_threads--;
        return 0;
}

Entry *directory_lookup(const Directory *d, const char *name) {
    int s=0;
    int e=d->entries;
    int cmp=-1;
    while(s<d->entries && s<e && 
	  (cmp=strcmp(d->array[(s+e)/2].name,name))!=0) {
	if (cmp<0) {
	    s=(s+e)/2+1;
	} else {
	    e=(s+e)/2;
	}
	/* assert(s<d->entries && e<=d->entries); */
    }
    if (cmp==0) return &d->array[(s+e)/2];
    return NULL;    
}

struct ThreadStatus
{
        pthread_mutex_t mut;
        char status[MAXLEN];
        struct ThreadStatus *prev;
        struct timespec job_start;
};
static _Thread_local struct ThreadStatus status = PTHREAD_MUTEX_INITIALIZER;
static struct ThreadStatus *first_status = NULL;

void set_thread_status_unlocked(const char *file, const char *s)
{
        snprintf(status.status, MAXLEN - 1, "%-12s : %.100s", s, (file) ? file : "");
}
void set_thread_status(const char *file, const char *s)
{
        if (progress < 3)
                return;
        pthread_mutex_lock(&status.mut);
        set_thread_status_unlocked(file, s);
        pthread_mutex_unlock(&status.mut);
}

void mark_job_start(const char *file, const char *s)
{
        pthread_mutex_lock(&status.mut);
        set_thread_status_unlocked(file, s);
        clock_gettime(CLOCK_BOOTTIME, &status.job_start);
        pthread_mutex_unlock(&status.mut);
}

/* Threads wait in this loop for jobs to run */
void *job_queue_loop(void *arg)
{

        pthread_mutex_lock(&mut);
        status.prev = first_status;
        first_status = &status;
        mark_job_start(NULL, "thread started");
        /* Loop until exit() is called*/
        while (1)
        {
                run_any_job();
        }
        /* Never return */
}

/* Submit a job:
 * Add it first to the job queue, so that we run jobs depth first.
 * Depth fist lets us close open directories earlier and save file descriptors.
 */
Job *submit_job_locked(Directory *from, Entry *fentry, Directory *to, const char *target, off_t offset, JobCallback *callback)
{
        assert(fentry);
        Job *job = my_calloc(1, sizeof(Job));

        job->tid=0;
        job->magick = 0x10b10b;
        job->from = from;
        job->fentry = fentry;
        job->to = to;
        job->target = target;
        job->offset = offset;
        job->callback = callback;
        job->state = JOB_WAITING;

        for (Job *queue_job = pre_scan_list; queue_job; queue_job = queue_job->next)
                assert(queue_job->magick == 0x10b10b);
        if (job->from)
                job->from->refs++;
        if (job->to)
                job->to->refs++;
        if (job->offset == DSYNC_FILE_WAIT || job->offset == DSYNC_DIR_WAIT)
        {
                assert(job->fentry->wait_queue == NULL);
                job->fentry->wait_queue = job; // Put it to wait queue
        }
        else if (fentry->job)
        {
                /* Put it last to its own Entry queue */
                Job *prev = fentry->job;
                while (prev->next && prev->next->fentry == fentry)
                        prev = prev->next;
                job->next = prev->next;
                prev->next = job;
        }
        else
        {
                /* Put it first to global queue, if there was not a fentry queue, to run jobs depth first */
                job->next = pre_scan_list;
                pre_scan_list = job;
                fentry->job = job;
        }
        for (Job *queue_job = pre_scan_list; queue_job; queue_job = queue_job->next)
                assert(queue_job->magick == 0x10b10b);

        scans.jobs++;
        if (++scans.queued > scans.maxjobs)
                scans.maxjobs = scans.queued;
        pthread_cond_broadcast(&cond);

        return job;
}

Job *submit_job(Directory *from, Entry *fentry, Directory *to, const char *target, off_t offset, JobCallback *callback) {
        pthread_mutex_lock(&mut);
        Job *j=submit_job_locked(from, fentry, to, target, offset, callback);
        pthread_mutex_unlock(&mut);
        return j;
}


/* wait for all jobs in the Entry to be done  */
int wait_for_entry(Entry *e)
{
        assert(e);
        int ret = 0;
        pthread_mutex_lock(&mut);
        Job *job = e->job;
        /* Run the whole job queue of Entry until it is empty or READY */
        while (job && job->fentry == e && job->state != JOB_READY && job->state != SCAN_READY)
        {
                switch (job->state)
                {
                case JOB_RUNNING:
                case SCAN_RUNNING:
                        /* Don't wait for ourselves */
                        if (job->tid==pthread_self()) {
                                job=job->next;
                                break; 
                        }
                        /* Run a job while we wait */
                        set_thread_status(file_path(job->from, job->fentry->name), "waiting");
                        run_any_job();
                        job = e->job; // Get the job again, it might have changed
                        break;
                case JOB_WAITING:
                case SCAN_WAITING:
                        run_one_job(job); // Run it ourselves
                        job = e->job;
                        break;
                case JOB_READY:
                case SCAN_READY:
                        job = job->next;
                default:
                        assert(0);
                        break;
                }
        }
        pthread_mutex_unlock(&mut);
        return ret;
}

/* Debugging. Assume mutex is held */
int print_jobs(FILE *f)
{
        int i = 0;
        struct timespec now;

        clock_gettime(CLOCK_BOOTTIME, &now);
        fprintf(f, "Thread: runtime : job\n");
        for (struct ThreadStatus *s = first_status; s; s = s->prev)
        {
                long long idle = (now.tv_sec - s->job_start.tv_sec) * 1000LL +
                                 (now.tv_nsec - s->job_start.tv_nsec) / 1000000LL;
                if (idle > 10000) {
                        fprintf(f, "%5d : %5llds  : %s\n", i, idle/1000, s->status);
                        // abort(); // Use to debug slow threads
                } else fprintf(f, "%5d : %5lldms : %s\n", i, idle, s->status);
                i++;
        }
        if (progress < 5)
                return 0;
        Job *j = pre_scan_list;
        i = 0;
        while (j)
        {
                fprintf(f, "Job %d: %s%s -> %s%s state=%d, offset=%ld, fentry=%p\n", i++, dir_path(j->from), j->fentry->name, dir_path(j->to), (j->target) ? j->target : "[NOTARGET]", j->state, j->offset, j->fentry);
                j = j->next;
        }
        return 0;
}

void start_job_threads(int job_threads, Job *job)
{
        pthread_t threads[job_threads];
        long long last_ns = 0;

        for (int i = 0; i < job_threads; i++)
        {
                if (pthread_create(&threads[i], NULL, job_queue_loop, NULL) < 0)
                {
                        perror("thread_create");
                        exit(1);
                }
        }
        // printf("Started %d job threads.\n",job_threads);
        pthread_mutex_lock(&mut);
        pthread_cond_broadcast(&cond); /* Kickstart the threads */
        /* Show progress until all jobs are finished. */
        while (scans.queued > 0)
        {
                assert(pre_scan_list);
                /* call show_progress() while waiting for the to finish */
                struct timespec ts;
                clock_gettime(CLOCK_REALTIME, &ts);
                long long now = ts.tv_sec * 1000000000L + ts.tv_nsec;
                if (now - last_ns > 1000000000)
                {
                        // FIXME we are calling print_progress with lock_held and that might hang IO
                        print_progress();
                        last_ns = now;
                }
                ts.tv_sec += +1;
                if (pthread_cond_timedwait(&cond, &mut, &ts) < 0 && errno == ETIMEDOUT)
                {
                        fprintf(stderr, "No IO in 1s. Slow fs or deadlock?\n");
                }
        }
        pthread_mutex_unlock(&mut);
}
