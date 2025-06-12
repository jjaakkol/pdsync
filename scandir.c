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
        if (job->from) d_freedir(job->from);
        if (job->to) d_freedir(job->to);
        int ret = job->ret;
        job->next = NULL;
        job->state = JOB_INVALID;
        job->magick = 1234569; /* Mark as a zombie */
        free(job);

        return ret;
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
                        /* The job for this directory has not started yet. Run it ourselves */
                        scans.pre_scan_misses++;
                        run_one_job(d);
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
                        d->next = pre_scan_list;
                        pre_scan_list = d;
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

        assert(result->ref>0);
        return result;
}

// Checks if the WaitQueue job should be run and add it to the global queue if yes
void job_check_wait_queue(Job *wj)
{
        Job *i;
        if (wj==NULL) return;
        // Find if there are any jobs to be waited left
        for (i = pre_scan_list; i; i = i->next)
        {
                if (wj->offset == DSYNC_FILE_WAIT && i->fentry == wj->fentry && i->state!=SCAN_READY && i->state!=JOB_READY)
                        break;
                if (wj->offset == DSYNC_DIR_WAIT && i->from && i->from->parent_entry==wj->fentry && i->state!=SCAN_READY && i->state!=JOB_READY)
                        break;
        }
        if (i == NULL)
        {
                // Schedule the job that was waiting
                //printf("wait queue job %s (%p) scheduled \n", file_path(wj->from, wj->fentry->name), wj);
                wj->next = pre_scan_list;
                pre_scan_list = wj;
                wj->fentry->wait_queue = NULL;
                scans.wait_queued--;
                scans.queued++;
                return;
        } else {
#if 0
                 printf("wait queue %ld job %s (%p) waiting for %s (%p) state=%d\n", wj->offset,
                        file_path(wj->from, wj->fentry->name), wj,  
                        file_path(i->from, i->fentry->name), i->fentry, i->state);
#endif
                return;
        }
}


/* Runs one job: can be called by a thread when waiting jobs to finish.
 * Assumes mutex is held.
 */
JobResult run_one_job(Job *j)
{
        assert(j && j->magick == 0x10b10b);
        Entry *fentry=j->fentry;
        Entry *parent_entry=(j->from) ? j->from->parent_entry : NULL;
        
        switch (j->state)
        {
        case SCAN_WAITING:
                j->state = SCAN_RUNNING;
                j->tid = pthread_self();
                mark_job_start(file_path(j->from, j->fentry->name), "readdir start");
                pthread_mutex_unlock(&mut);
                j->result = scan_directory(j->from, j->fentry);
                pthread_mutex_lock(&mut);
                set_thread_status(file_path(j->from, j->fentry->name), "scanned dir");
                j->state = SCAN_READY;
                scans.queued--;
                pthread_cond_broadcast(&cond);
                if (fentry) job_check_wait_queue(fentry->wait_queue);
                if (parent_entry) job_check_wait_queue(parent_entry->wait_queue);
                return RET_OK;
                break;

        case JOB_WAITING:
                assert(j->magick == 0x10b10b);
                assert(j->fentry);
                j->state = JOB_RUNNING;
                j->tid = pthread_self();
                mark_job_start(file_path(j->from, j->fentry->name), "job start");
                pthread_mutex_unlock(&mut);
                j->ret = j->callback(j->from, j->fentry, j->to, j->target, j->offset);
                pthread_mutex_lock(&mut);
                j->state = JOB_READY;
                scans.queued--;
                pthread_cond_broadcast(&cond);
                if (fentry) job_check_wait_queue(fentry->wait_queue);
                if (parent_entry) job_check_wait_queue(parent_entry->wait_queue);
                free_job(j); /* If we ever need a mechanism to wait for job status, we could keep the job as a zombie job */
                return RET_OK;

        default:
                return RET_NONE;
        }
        // Never here
}

/* This is called:
 * - by the job queue thread to run jobs
 * - when threads are waiting for another thread to finish a job
 * This is called with the lock held.
 * This is where we would apply a scheduling policy, if there was one.
 */
JobResult run_any_job()
{
        Job *j;
        static _Thread_local JobCallback *last_job=NULL;

        // First try to run something different than last time to keep IO queue full
        for (j = pre_scan_list; j; j = j->next)
        {
                if ((j->state == SCAN_WAITING || j->state == JOB_WAITING) && j->callback!=last_job) {
                        last_job=j->callback;
                        return run_one_job(j);
                }
        }
        // Then run anything. 
        for (j = pre_scan_list; j; j = j->next)
        {
                if (j->state == SCAN_WAITING || j->state == JOB_WAITING) 
                        return run_one_job(j);
        }

        /* No jobs to run, we wait */
        mark_job_start(NULL, "idle");
        scans.idle_threads++;
        pthread_cond_wait(&cond, &mut);
        scans.idle_threads--;
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

        //for (Job *queue_job = pre_scan_list; queue_job; queue_job = queue_job->next)
        //        assert(queue_job->magick == 0x10b10b);
        if (job->from)
                dir_claim(job->from);
        if (job->to)
                dir_claim(job->to);
        if (job->offset == DSYNC_FILE_WAIT || job->offset == DSYNC_DIR_WAIT)
        {
                assert(job->fentry->wait_queue == NULL);
                job->fentry->wait_queue = job; // Put it to wait queue
                scans.wait_queued++;
                //printf("wait queue job %p for %p submitted. queued=%5d\n", job, job->fentry, scans.wait_queued);
                job_check_wait_queue(job); // Check and schedule it normally, if it can be run immediately.
                return job; 
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
                /* If there was not a fentry queue, put it to global queue, to run jobs depth first */
                job->next = pre_scan_list;
                pre_scan_list = job;
                fentry->job = job;
        }
        // for (Job *queue_job = pre_scan_list; queue_job; queue_job = queue_job->next)
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
        assert(scans.wait_queued==0);
        pthread_mutex_unlock(&mut);
        //assert(pre_scan_list==NULL);
}
