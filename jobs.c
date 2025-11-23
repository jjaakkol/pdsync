#include "dsync.h"
#include <sys/syscall.h>
#include <sys/types.h>

typedef enum
{
        JOB_WAITING,
        JOB_RUNNING,
        JOB_READY,
        JOB_INVALID /* Catch use after frees */
} JobState;

typedef struct JobStruct
{
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


static pthread_mutex_t mut = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
static Job *first_job = NULL;
static Job *last_job=NULL;

void job_lock(void) {
        pthread_mutex_lock(&mut);
}

void job_unlock(void) {
        int rc = pthread_mutex_trylock(&mut);
        assert(rc == EBUSY);
        pthread_mutex_unlock(&mut);
}

// Threads status counting, mostly for debugging and progress reporting
struct ThreadStatus
{
        pthread_mutex_t mut;
        char status[MAXLEN];
        struct ThreadStatus *prev;
        struct timespec job_start;
        pid_t tid;
        int idle;
};
static _Thread_local struct ThreadStatus this_thread = PTHREAD_MUTEX_INITIALIZER;
static struct ThreadStatus *first_status = NULL;

void set_thread_status_f(const char *file, const char *s, const char *func, int mark)
{
        if (progress < 2 && debug==0)
                return;
        if (mark) clock_gettime(CLOCK_BOOTTIME, &this_thread.job_start);
        snprintf(this_thread.status, MAXLEN - 1, "%14s(): %-14s : %.100s", func, s, (file) ? file : "");
        if (debug) fprintf(stderr, "Debug: %s\n", this_thread.status);
}


// If Directory's Job's have been done, release its last job to queue
// Also do this to parent directories.
// Mutex must be held.
void release_jobs(Directory *d) {
        if (d->parent) release_jobs(d->parent);
        d->jobs--;
        if (debug) fprintf(stderr,"release_job: %d/%d left: %s (%p)\n", d->jobs, scans.queued, dir_path(d), d->last_job);    
        if (d->jobs==0 && d->last_job) {
                d->last_job->next=first_job;
                first_job=d->last_job;
                if (last_job==NULL) last_job=first_job;
                d->last_job=NULL;
                scans.jobs_waiting--;
        }
}

/* Remove job from queue's and free its resources. Mutex must be held. */
int free_job(Job *job)
{
        assert(job);
        assert(job->fentry);
        assert(job->state == JOB_READY);
        assert(job->magick == 0x10b10b);

        if (debug) fprintf(stderr,"Debug: free_job  from=%p %s\n", job->from,  file_path(job->from, job->fentry->name));
        /* Remove job from Job queue */
        scans.queued--;
        if (first_job == job) {
                first_job = job->next;
                if (first_job==NULL) last_job=NULL;
        } else
        {
                Job *prev = first_job;
                assert(prev->magick == 0x10b10b);
                while (prev->next != job)
                        prev = prev->next;
                assert(prev); // the job must be in the list
                prev->next = job->next;
                if (job==last_job) last_job=prev;
        } 
        if (job->fentry->dir) {
                if (debug) fprintf(stderr,"Debug: releasing job: from=%p %s\n", job->from,  dir_path(job->fentry->dir));
                release_jobs(job->fentry->dir);
        } else if (job->from) release_jobs(job->from);
        if (job->from) d_freedir(job->from);
        if (job->to) d_freedir(job->to);
        int ret = job->ret;
        job->next = NULL;
        job->state = JOB_INVALID;
        job->magick = 1234569; /* Mark as a zombie */
        free(job);
        return ret;
}


/* Runs one job: can be called by a thread when waiting jobs to finish.
 * Assumes mutex is held.
 */
JobResult run_one_job(Job *j)
{
        assert(j && j->magick == 0x10b10b);
        Entry *fentry=j->fentry;
        
        switch (j->state)
        {
        case JOB_WAITING:
                assert(j->magick == 0x10b10b);
                assert(j->fentry);
                if (j->fentry->state!=ENTRY_FAILED) {
                        /* No point in running job if there was an error */
                        j->state = JOB_RUNNING;
                        mark_job_start(file_path(j->from, j->fentry->name), "job start");
                        pthread_mutex_unlock(&mut);
                        j->ret = j->callback(j->from, j->fentry, j->to, j->target, j->offset);
                        pthread_mutex_lock(&mut);
                        mark_job_start(file_path(j->from, j->fentry->name), "job ended");
                }
                j->state = JOB_READY;
                JobResult ret= (fentry->state==ENTRY_FAILED) ? RET_FAILED : RET_OK;
                free_job(j); /* If we ever need a mechanism to wait for job status, we could keep the job as a zombie job */
                pthread_cond_broadcast(&cond);
                return ret;

        default:
                return RET_NONE;
        }
        // Never here
}

/* This is called:
 * - by the job queue thread to run jobs
 * - when threads are waiting for another thread to finish a job
 * This is called with the lock held.
 * This is where we would apply a Job scheduling policy, if there was one.
 */
JobResult run_any_job()
{
        mark_job_start(NULL,"select job");
        Job *j=first_job;
        for(; j && j->offset==DSYNC_FILE_WAIT ; j=j->next) {
                if (j->state == JOB_WAITING)
                        return run_one_job(j); // First runnable file waiting job is done waiting for others
        }
        for (; j; j=j->next) {
                if ( (j->state == JOB_WAITING) &&
                        j->offset!=DSYNC_FILE_WAIT)
                        return run_one_job(j); /* First runnable which is not waiting for other jobs */
        }

        /* No jobs to run. We need to wait and release the lock. */
        mark_job_start(NULL, NULL);
        // TODO: remove scans.idle_threads since we want better thread status counting anyway
        scans.idle_threads++;
        this_thread.idle=1;
        pthread_cond_wait(&cond, &mut);
        this_thread.idle=0;
        scans.idle_threads--;
        mark_job_start(NULL, "idle done");
        return RET_NONE;
}

Entry *directory_lookup(const Directory *d, const char *name) {
    int s=0;
    int e=d->entries;
    int cmp=-1;
    while(s<d->entries && s<e && 
	  (cmp=strcmp(d->sorted[(s+e)/2]->name,name))!=0) {
	if (cmp<0) {
	    s=(s+e)/2+1;
	} else {
	    e=(s+e)/2;
	}
	/* assert(s<d->entries && e<=d->entries); */
    }
    if (cmp==0) return d->sorted[(s+e)/2];
    return NULL;    
}

/* Threads wait in this loop for jobs to run */
void *job_queue_loop(void *arg)
{

        pthread_mutex_lock(&mut);
        this_thread.prev = first_status;
        first_status = &this_thread;
        this_thread.tid = (pid_t)syscall(SYS_gettid); // gettid() is Linux specific and is not in older glibcs
        mark_job_start(NULL, "thread started");
        /* Loop until exit() is called*/
        while (1) run_any_job();
        /* Never return */
}

// Create a new job and init it. 
Job *create_job(Directory *from, Entry *fentry, Directory *to, const char *target, off_t offset, JobCallback *callback)
{
        assert(fentry);
        Job *job = my_calloc(1, sizeof(Job));

        job->magick = 0x10b10b;
        job->from = from;
        job->fentry = fentry;
        job->to = to;
        job->target = target;
        job->offset = offset;
        job->callback = callback;
        job->state = JOB_WAITING;

        //for (Job *queue_job = first_job; queue_job; queue_job = queue_job->next)
        //        assert(queue_job->magick == 0x10b10b);
        if (job->from)
                dir_claim(job->from);
        if (job->to)
                dir_claim(job->to);
        for(Directory *d=job->from; d; d=d->parent) d->jobs++;
        if (fentry->dir) {
                fentry->dir->jobs++;
                dir_claim(fentry->dir);
        }

        scans.jobs++;
        if (++scans.queued > scans.maxjobs)
                scans.maxjobs = scans.queued;

        return job;
}

Job *submit_job(Directory *from, Entry *fentry, Directory *to, const char *target, off_t offset, JobCallback *callback) {
        DEBUG("submit_job: from=%s, fentry=%s to=%s, target=%s, offset=%ld callback=%p\n", dir_path(from), fentry->name, dir_path(to), target, offset, callback);
        job_lock();
        Job *job=create_job(from, fentry, to, target, offset, callback);
        if (offset==DSYNC_DIR_WAIT) {
                assert(fentry && fentry->dir && fentry->dir->last_job==NULL);
                fentry->dir->last_job=job;
                scans.jobs_waiting++;
        } else if (first_job==NULL) {
                first_job=last_job=job;
        } else {
                assert(last_job && last_job->next==NULL);
                last_job->next=job;
                last_job=job;
        }
        /*for (Job *queue_job = first_job; queue_job; queue_job = queue_job->next) {
                assert(queue_job->magick == 0x10b10b);
        }*/
        pthread_cond_broadcast(&cond);
        job_unlock();
        return job;
}

Job *submit_job_first(Directory *from, Entry *fentry, Directory *to, const char *target, off_t offset, JobCallback *callback) {
        DEBUG("from=%s, fentry=%s to=%s, target=%s, offset=%ld callback=%p\n", dir_path(from), fentry->name, dir_path(to), target, offset, callback);
        job_lock();
        Job *job=create_job(from, fentry, to, target, offset, callback);
        if (first_job==NULL) {
                first_job=last_job=job;
        } else {
                job->next=first_job;
                first_job=job;
        }
        /*for (Job *queue_job = first_job; queue_job; queue_job = queue_job->next) {
                assert(queue_job->magick == 0x10b10b);
        }*/
        pthread_cond_broadcast(&cond);
        job_unlock();
        return job;
}

// Lock should be held, but probably works anyway
int count_stalled_threads() {
        int count = 0;
        struct timespec now;
        clock_gettime(CLOCK_BOOTTIME, &now);

        for (struct ThreadStatus *s = first_status; s; s = s->prev)
        {
                if (s->idle) continue; // Skip idle threads
                long long idle = (now.tv_sec - s->job_start.tv_sec) * 1000LL +
                                 (now.tv_nsec - s->job_start.tv_nsec) / 1000000LL;
                if (idle > 10000) count++;
        }
        return count;
}

// Useful for seeing IO stalls and debugging
int print_jobs(FILE *f)
{
        struct timespec now;
        clock_gettime(CLOCK_BOOTTIME, &now);

        if (progress>=4) {
                fprintf(f, "TID     : runtime : job\n");
        } else if (progress>=3 && count_stalled_threads()>0) {
                fprintf(f, "TID     : runtime : stalled jobs\n");
        } else return 0;

        for (struct ThreadStatus *s = first_status; s; s = s->prev)
        {
                if (s->idle) continue; /* Skip idle threads */
                long long idle = (now.tv_sec - s->job_start.tv_sec) * 1000LL +
                                 (now.tv_nsec - s->job_start.tv_nsec) / 1000000LL;
                if (idle > 10000) {
                        fprintf(f, "%7d : %5llds! : %s\n", s->tid, idle/1000, s->status);
                } else if (progress>=4) {
                        fprintf(f, "%7d : %5lldms : %s\n", s->tid, idle, s->status);
                }
        }
        if (progress < 5)
                return 0;

        int i=0;
        for (Job *j=first_job; j; j=j->next, i++) {
                fprintf(f, "Job %d: %s%s -> %s%s state=%d, offset=%ld, fentry=%p\n", i, dir_path(j->from), j->fentry->name, 
                        (j->to) ? dir_path(j->to) :"NULL", (j->target) ? j->target : "[NOTARGET]", j->state, j->offset, j->fentry);
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
                assert(first_job);
                struct timespec ts;
                clock_gettime(CLOCK_REALTIME, &ts);
                long long now = ts.tv_sec * 1000000000L + ts.tv_nsec;
                if (now - last_ns > 1000000000)
                {
                        // FIXME we are calling print_progress with lock_held and that might hang IO
                        print_progress();
                        last_ns = now;
                }
                ts.tv_sec+=1;
                if (pthread_cond_timedwait(&cond, &mut, &ts)==ETIMEDOUT)
                {
                        fprintf(stderr, "Slow IO detected. No jobs finished in 1s. %d idle threads.\n", scans.idle_threads);
                        scans.slow_io_secs++;
                }
        }
        pthread_mutex_unlock(&mut);
}
