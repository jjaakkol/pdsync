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


static pthread_mutex_t mut = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
static Job *pre_scan_list = NULL;
static Job *last_job=NULL;

void job_lock(void) {
        pthread_mutex_lock(&mut);
}

void job_unlock(void) {
        int rc = pthread_mutex_trylock(&mut);
        assert(rc == EBUSY);
        pthread_mutex_unlock(&mut);
}

/* Remove job from queue's and free its resources. Mutex must be held. */
int free_job(Job *job)
{
        assert(job);
        assert(job->fentry);
        assert(job->state == JOB_READY || job->state == SCAN_READY);
        assert(job->magick == 0x10b10b);

        /* If job is last in its fentry queue the fentry queue is done and can be marked empty */
        if (job->fentry->last_job == job) job->fentry->last_job=NULL;

        /* Remove job from pre_scan_list Job queue */
        if (pre_scan_list == job) {
                pre_scan_list = job->next;
                if (pre_scan_list==NULL) last_job=NULL;
        } else
        {
                Job *prev = pre_scan_list;
                assert(prev->magick == 0x10b10b);
                while (prev->next != job)
                        prev = prev->next;
                assert(prev); // the job must be in the list
                prev->next = job->next;
                if (job==last_job) last_job=prev;
        }

        /* Freedir counts references */
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
        case SCAN_WAITING:
                j->state = SCAN_RUNNING;
                j->tid = pthread_self();
                mark_job_start(file_path(j->from, j->fentry->name), "readdir start");
                pthread_mutex_unlock(&mut);
                j->result = scan_directory(j->from, j->fentry);
                pthread_mutex_lock(&mut);
                j->state = SCAN_READY;
                scans.queued--;
                pthread_cond_broadcast(&cond);
                return RET_OK;
                break;

        case JOB_WAITING:
                assert(j->magick == 0x10b10b);
                assert(j->fentry);
                if (j->fentry->state!=ENTRY_FAILED) {
                        /* No point in running job if there was an error */
                        j->state = JOB_RUNNING;
                        j->tid = pthread_self();
                        mark_job_start(file_path(j->from, j->fentry->name), "job start");
                        pthread_mutex_unlock(&mut);
                        j->ret = j->callback(j->from, j->fentry, j->to, j->target, j->offset);
                        pthread_mutex_lock(&mut);
                }
                j->state = JOB_READY;
                scans.queued--;
                pthread_cond_broadcast(&cond);
                JobResult ret= (fentry->state==ENTRY_FAILED) ? RET_FAILED : RET_OK;
                free_job(j); /* If we ever need a mechanism to wait for job status, we could keep the job as a zombie job */
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
        Job *j=pre_scan_list;
        while(j && j->state==SCAN_READY) j=j->next; // Skip ready jobs to find first runnable job
        for(; j && j->offset==DSYNC_FILE_WAIT ; j=j->next) {
                if (j->state == JOB_WAITING)
                        return run_one_job(j); // First runnable file waiting job is done waiting for others
        }
        for(; j && j->offset==DSYNC_DIR_WAIT ; j=j->next) {
                if (j->state == JOB_WAITING)
                        return run_one_job(j); // First runnable directory waiting job is done waiting for others
        }
        for (; j; j=j->next) {
                if ( (j->state == SCAN_WAITING || j->state == JOB_WAITING) &&
                        j->offset!=DSYNC_FILE_WAIT && j->offset!=DSYNC_DIR_WAIT )
                        return run_one_job(j); /* First runnable which is not waiting for other jobs */
        }

        /* No jobs to run. We need to wait and release the lock. */
        mark_job_start(NULL, "idle");
        scans.idle_threads++;
        pthread_cond_wait(&cond, &mut);
        scans.idle_threads--;
        return RET_NONE;
#if 0
        static _Thread_local JobCallback *last_job=NULL;
        // First try to run something different than last time to keep IO queue full
        for (j = pre_scan_list; j; j = j->next)
        {
                if ((j->state == SCAN_WAITING || j->state == JOB_WAITING) && j->callback!=last_job) {
                        last_job=j->callback;
                        return run_one_job(j);
                }
        }
#endif
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

struct ThreadStatus
{
        pthread_mutex_t mut;
        char status[MAXLEN];
        struct ThreadStatus *prev;
        struct timespec job_start;
};
static _Thread_local struct ThreadStatus status = PTHREAD_MUTEX_INITIALIZER;
static struct ThreadStatus *first_status = NULL;

void set_thread_status_f(const char *file, const char *s, const char *func, int mark)
{
        if (progress < 3)
                return;
        if (mark) clock_gettime(CLOCK_BOOTTIME, &status.job_start);
        snprintf(status.status, MAXLEN - 1, "%12s():%-12s : %.100s", func, s, (file) ? file : "");
}

/* Threads wait in this loop for jobs to run */
void *job_queue_loop(void *arg)
{

        pthread_mutex_lock(&mut);
        status.prev = first_status;
        first_status = &status;
        mark_job_start(NULL, "thread started");
        /* Loop until exit() is called*/
        while (1) run_any_job();
        /* Never return */
}

// Submit a job as last in in its own fentry or global last
// Fentry and global lists form a single list of jobs.
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

        //for (Job *queue_job = pre_scan_list; queue_job; queue_job = queue_job->next)
        //        assert(queue_job->magick == 0x10b10b);
        if (job->from)
                dir_claim(job->from);
        if (job->to)
                dir_claim(job->to);

        if (pre_scan_list==NULL) pre_scan_list=last_job=job;
#if 0
        else if (fentry->last_job)
        {
                /* Put it last to its own Entry queue */
                job->next=fentry->last_job->next;
                fentry->last_job->next=job;
                fentry->last_job=job;
                if (last_job->next==job) last_job=job;
        }
#endif
        else
        {
                /* If there was not a fentry queue, put it last to global queue */
                if (last_job) last_job->next=job;
                last_job=job;
        }
        //for (Job *queue_job = pre_scan_list; queue_job; queue_job = queue_job->next)
        //      assert(queue_job->magick == 0x10b10b);


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


#if 0
// This needs to go way probably */
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
#endif

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
                fprintf(f, "Job %d: %s%s -> %s%s state=%d, offset=%ld, fentry=%p\n", i++, dir_path(j->from), j->fentry->name, 
                        (j->to) ? dir_path(j->to) :"NULL", (j->target) ? j->target : "[NOTARGET]", j->state, j->offset, j->fentry);
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
                ts.tv_sec+=1;
                if (pthread_cond_timedwait(&cond, &mut, &ts)==ETIMEDOUT)
                {
                        fprintf(stderr, "Slow IO detected. No jobs finished in 1s. %d idle threads.\n", scans.idle_threads);
                        scans.slow_io_secs++;
                }
        }
        pthread_mutex_unlock(&mut);
        //assert(pre_scan_list==NULL);
}
