#include "dsync.h"

typedef enum {
    SCAN_WAITING,
    SCAN_RUNNING,
    SCAN_READY,
    JOB_WAITING,
    JOB_RUNNING,
    JOB_READY,
    JOB_INVALID /* Catch use after frees */
} JobState;

typedef struct JobStruct {
    Directory *from;
    Entry *fentry;
    Directory *to;
    const char *target;
    Directory *result;
    JobState state;
    struct JobStruct *next;
    JobCallback *callback;
    off_t offset;
    int ret;
} Job;


pthread_mutex_t mut = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
Job *pre_scan_list=NULL;

static int my_strcmp(const void *x, const void *y) {
    const char *a=*(const char **)x;
    const char *b=*(const char **)y;
    return strcmp(a,b);
}

const char *dir_path(const Directory *d) {
        _Thread_local static char buf[MAXLEN];
        _Thread_local static int len;
        if (d) {
                dir_path(d->parent);
                len+=snprintf(buf+len,MAXLEN-len,"%s/",d->name);
        } else len=snprintf(buf,MAXLEN,"%s","");
        return buf; 
}

void show_error_dir(const char *message, const Directory *parent, const char *file) {
        fprintf(stderr,"Error: %s : %s : %s%s\n",message,strerror(errno),dir_path(parent),file);
}

/* Free a directory structure */
void d_freedir(Directory *dir) {
        pthread_mutex_lock(&mut);

        assert(dir->magick==0xDADDAD);

        while(dir->entries>0) {
	        dir->entries--;
	        if (dir->array[dir->entries].link) free(dir->array[dir->entries].link);
                if (dir->array[dir->entries].job) {
                        fprintf(stderr,"BUG: a job is still running in %s%s\n",dir_path(dir), dir->array[dir->entries].name);
                }
                free(dir->array[dir->entries].name);

        }
        free(dir->array);

        dir->magick=0xDADDEAD;
        if (dir->handle) closedir(dir->handle);

        if (dir->refs>0) {
                fprintf(stderr,"BUG: Caught a still referenced zombie Directory: %d refs %s%s\n",dir->refs,dir_path(dir),dir->name);
        }
        free(dir->name);
        dir->entries=-123; /* Magic value to debug a race */
        if (dir->parent) { 
                dir->parent->refs--;
                if (dir->parent->magick==0xDADDEAD) fprintf(stderr,"BUG: Directory * parent is a zombie\n");
        }
        free(dir);

        scans.dirs_active--;

        pthread_mutex_unlock(&mut);

}

/* Initialize a directory Entry. */
Entry *init_entry(Entry * entry, int dfd, char *name) {
        memset(entry,0,sizeof (* entry));
        entry->name=name;

	if (fstatat(dfd, name, &entry->stat, AT_SYMLINK_NOFOLLOW)<0) {
                entry->error=errno;
	        show_error("fstatat",name);
	} else if (S_ISLNK(entry->stat.st_mode)) {
	    /* Read the symlink if there is one. FIXME: maybe skip this if we don't have --preserve-links */
	    char linkbuf[MAXLEN];
	    int link_len;

	    if ( (link_len=readlinkat(dfd, name, linkbuf, sizeof(linkbuf)-1)) <=0 ) {
		/* Failed to read link. */
		show_error("readlink",name);
		/* FIXME: read errors is not visible here: 
                opers.read_errors++; */
	    } else {
		/* Save the link */
                entry->link=my_malloc(link_len+1);
		memcpy(entry->link, linkbuf, link_len);
		entry->link[link_len]=0;
	    }
	}
        scans.entries_scanned++;
        return entry;
}

/* scan_directory can be called from multiple threads */
Directory *scan_directory(const char *name, Directory *parent) {
    DIR *d=NULL;
    int dfd=-1;
    Directory *nd=NULL;
    struct dirent *dent;
    int i;
    int allocated=16;
    int entries=0;
    char **names=NULL;

    assert(!parent || parent->magick!=0xDADDEAD);

    /* Assume that the parent has not freed yet by other threads. */
    assert(!parent || parent->magick==0xDADDAD);

     /* TODO: should the O_NOATIME be a flag*/
    dfd=openat( (parent) ? dirfd(parent->handle) : AT_FDCWD , name, O_NOFOLLOW|O_RDONLY|O_DIRECTORY);
    //printf("Scanning directory %s%s\n", dir_path(parent), name);
    if (dfd<0) {
        show_error_dir("opendir",parent,name);
        return NULL;
    }
    d=fdopendir(dfd);
    if (!d) {
        show_error_dir("fdopenbdir", parent,name);
        close(dfd);
        return NULL;
    }

    if ( (names=malloc(sizeof(char *)*allocated)) ==NULL) {
	goto fail;
    }

    /* Allocate the Directory structure */
    if ( ! (nd=malloc(sizeof(Directory))) ) {
	goto fail;
    }
    nd->parent=parent;
    nd->name=my_strdup(name);
    nd->handle=d;
    nd->refs=0;

    /* scan the directory */
    while( (dent=readdir(d)) ) {
	if (entries==allocated) {
	    /* Allocate more space for names */
	    char **tmp_names=NULL;
	    
	    allocated+=allocated/2;
	    tmp_names=my_realloc(names,sizeof(char *)*allocated);
	    names=tmp_names;	    
	}
	if (dent->d_name[0]=='.') {
	    /* Skip '.' and '..' */
	    if (dent->d_name[1]==0) continue; 
	    if (dent->d_name[1]=='.' && dent->d_name[2]==0) continue;
	}
	if ( (names[entries]=my_strdup(dent->d_name))==NULL ) goto fail;
	entries++;
    } 

    /* TODO: maybe stat the directories first, then sort them */
    /* Sort the directory entries */
    qsort(names,entries,sizeof(names[0]),my_strcmp);    

    nd->array=my_malloc(entries * sizeof(Entry));
    nd->entries=entries;

    /* Initialize all entries in a directory  */
    for (i=0;i<nd->entries;i++) {
	assert(i==0 || my_strcmp(&names[i-1],&names[i])<0);
        init_entry(&nd->array[i], dfd, names[i]);
    }

    /* Names is no longer needed */
    free(names);
    names=NULL;
    scans.dirs_scanned++;

    nd->magick=0xDADDAD;
    pthread_mutex_lock(&mut);
    if (++scans.dirs_active > scans.dirs_active_max) scans.dirs_active_max=scans.dirs_active;
    pthread_mutex_unlock(&mut);
    
    return nd;

    fail:
    /* Something did not work out. Clean up */
    if (nd) {
        if (nd->array) {
                for(int i=0; nd->array && i<nd->entries;i++) {
                        if (nd->array[i].name) free(nd->array[i].name);
	                if (nd->array[i].link) free(nd->array[i].link);
                }
	        free(nd->array);
        }
    }
    while(entries>0) {
	entries--;
	free(names[entries]);
    }
    if (names) free(names);
    if (d) closedir(d);
    return NULL;
}

/* Remove job from queue's and free its resources. Mutex must be held. */
int free_job(Job *job) {
        assert(job->state==JOB_READY || job->state==SCAN_READY);
        assert(job->fentry->job == NULL || job->fentry->job!=job);
        if (job==pre_scan_list) pre_scan_list=job->next;
        else {
                Job *prev=pre_scan_list;
                assert(prev); // the job must be in the list
                while (prev->next != job) prev=prev->next;
                prev->next=job->next;
        }
        int ret=job->ret;
        job->next=NULL;
        job->state=JOB_INVALID;
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
Directory *pre_scan_directory(Directory *parent, Entry *dir) {
        Directory *result=NULL;
        const char *path=dir->name;
        int i;

        /* Lock the job list */
        pthread_mutex_lock(&mut);

        if (dir->job) {
                Job *d=dir->job;
                assert (d->state==SCAN_WAITING || d->state==SCAN_RUNNING || d->state==SCAN_READY);

	        /* We found our prescan job. */
	        switch(d->state) {
	        case SCAN_WAITING:
	                /* The job for this directory has not started yet. We run it in this thread later */
	                scans.pre_scan_misses++;
	                break;
	        case SCAN_RUNNING:
	                /* Scan had already started. Wait for the scanning thread to finish */
	                scans.pre_scan_wait_hits++;
	                while(d->state!=SCAN_READY) {
                                /* FIXME: do something useful here */
		                pthread_cond_broadcast(&cond);
		                pthread_cond_wait(&cond,&mut);
	                }
	                break;
	        case SCAN_READY:
                        /* The scan has finished */
	                scans.pre_scan_hits++;
	                break;
                default: assert(0); /* Silence a warning*/
                }
                result=d->result; /* Might be NULL in case of error */
                d->state=SCAN_READY;
                if (dir->job && dir->job->next && dir->job->next->fentry==dir) dir->job=dir->job->next; /* Remove the job from the list */
                else dir->job=NULL; /* The next job in the list was some other entry's job */
                free_job(d);
                d=NULL;
	        scans.pre_scan_used++;
        }    

        pthread_mutex_unlock(&mut); /* Do not lock the critical section during IO or scan_directory*/

        /* Reopen the DIR * handle of prescanned directories. */
        if (result && result->handle==NULL) {
                assert(result->parent && result->parent->magick==0xDADDAD && result->parent->handle);
                int dfd=openat(dirfd(result->parent->handle), dir->name, O_DIRECTORY|O_RDONLY|O_NOFOLLOW);
                struct stat dirstat,parentstat;
                if (dfd<0 || 
                        fstatat(dfd,"..",&dirstat,AT_SYMLINK_NOFOLLOW)<0 || 
                        fstat(dirfd(result->parent->handle),&parentstat)<0 ||
                        dirstat.st_dev!=parentstat.st_dev || dirstat.st_ino != parentstat.st_ino) {
                        show_error("directory has changed.",path);
                        d_freedir(result);
                        return NULL;
                }
                if (! (result->handle=fdopendir(dfd)) ) {
                        show_error("fdopendir",path);
                        close(dfd);
                        d_freedir(result);
                        return NULL;
                }

        } else {
	        /* The directory was not in queue or was not started. Scan it in this thread*/
	        scans.pre_scan_misses++;
                // printf("Miss: %s %s\n",path,basename);
	        result=scan_directory(path,parent);
        }

        pthread_mutex_lock(&mut); /* Need mutex to add new jobs */
   
        if (result==NULL) goto out;
        if (result->parent) result->parent->refs++;

        /* Now add the newly found directories to the job queue for prescanning*/
        for(i=result->entries-1; i>=0; i--) {
	        if (S_ISDIR(result->array[i].stat.st_mode)) {
                        if (result->array[i].job) {
                                scans.pre_scan_too_late++;
                                /* Already has a job, skip it */
                                continue;
                        }
                        Job *d=my_calloc(1,sizeof(*d));
                        d->fentry=&result->array[i];
                        result->array[i].job=d; /* Link the entry to the job */
                        d->from=result;
	                d->result=NULL;
	                d->state=SCAN_WAITING;
                        d->callback=NULL;
	                d->next=pre_scan_list;
	                pre_scan_list=d;
	                scans.pre_scan_allocated++;
	        }
        }
    
out:
        if (pre_scan_list) {
	        /* Kick the work queue thread */
	        pthread_cond_broadcast(&cond);
        }
        pthread_mutex_unlock(&mut);
        return result;
}

/* Runs one job: can be called by a thread when waiting jobs to finish.
 * Assumes mutex is held.
 */
 int run_one_job(Job *j) {
        switch(j->state) {

        case SCAN_WAITING:
                j->state=SCAN_RUNNING;
                pthread_mutex_unlock(&mut);
                j->result=scan_directory(j->fentry->name,j->from);
                /* Don't keep prescanned directories open to conserve filedescriptos */
                if (j->result) {
                        if (j->result->handle) closedir(j->result->handle);
                        j->result->handle=NULL;
                }
                pthread_mutex_lock(&mut);
                j->state=SCAN_READY;
                pthread_cond_broadcast(&cond);
                return 1;

        case JOB_WAITING:
                j->state=JOB_RUNNING;
                assert(j->from && j->fentry);
                pthread_mutex_unlock(&mut);
                j->ret=j->callback(j->from, j->fentry, j->to, j->target, j->offset);
                pthread_mutex_lock(&mut);
                j->state=JOB_READY;
                pthread_cond_broadcast(&cond);
                return 1;

        default:

        }
        return 0;
 }

 int run_any_job() {
        for (Job *j=pre_scan_list; j && j->state==SCAN_WAITING; j=j->next) {
                if (run_one_job(j)) return 1; // We ran a scan job
        }
        for (Job *j=pre_scan_list; j && j->state==JOB_WAITING; j=j->next) {
                if (run_one_job(j)) return 1; // We ran a callback job
        }
        /* No jobs to run */
        return 0;
 }

/* Threads wait in this loop for jobs to run */
void *job_queue_loop(void *arg) {

        pthread_mutex_lock(&mut);
        /* Loop until exit() is called*/
        while(1) {
                if (!run_any_job()) {
                        /* No jobs to run. Wait for something to come to the queue */
                        pthread_cond_wait(&cond,&mut);
                        continue;
                }
        }

    /* Never return */
}

/* Submit a job:
 * Add it last to the job queue of the Entry
 * if the entry queue was empty add it last to the global list
 */
Job *submit_job(Directory *from, Entry *fentry, Directory *to, const char *target, off_t offset, JobCallback *callback) {
        assert(from);
        Job *job=my_calloc(1, sizeof (Job));

        job->from=from;
        job->fentry=fentry;
        job->to=to;
        job->target=target;
        job->offset=offset;
        job->callback=callback;
        job->state=JOB_WAITING;

        pthread_mutex_lock(&mut);
        if (fentry->job) {
                Job *prev=fentry->job;
                while (prev->next && prev->next->fentry == fentry) prev=prev->next;
                job->next=prev->next;
                prev->next=job;
        } else { 
                Job *last=pre_scan_list;
                job->next=NULL;
                if (last) {
                        while (last->next) last=last->next;
                        last->next=job;
                } else {
                        pre_scan_list=job; // First job in the queue
                }
                fentry->job=job; 
        }
        if ( ++scans.jobs > scans.maxjobs ) scans.maxjobs=scans.jobs;
        pthread_mutex_unlock(&mut); 
        pthread_cond_broadcast(&cond);

        return job;
}

/* wait for all jobs in the entry to be done  */
int wait_for_entry(Entry *e) {
       assert(e);
       int ret=0;
       pthread_mutex_lock(&mut);
       Job *job=e->job;
       /* Run the whole job queue of Entry until it is empty or ready */
       while(job && job->fentry == e ) {
                switch(job->state) {
                        case JOB_RUNNING:
                        case SCAN_RUNNING:
                                /* Run a job while we wait */
                                if (!run_any_job()) {
                                        // Nothing to run. We have to wait.
		                        pthread_cond_broadcast(&cond);
		                        pthread_cond_wait(&cond,&mut);
                                }
                                job=e->job; // Get the job again, it might have changed
                                break;
                        case JOB_WAITING:
                        case SCAN_WAITING:
                                run_one_job(job); // Run it ourselves
                                job=e->job;
                                break;
                        case JOB_READY:
                        case SCAN_READY:
                                job=job->next; // Move to the next job
                                break;
                        default:
                                assert(0);
                                break;
                }
        }
        /* Same loop, but this time we free the ready jobs */
        job=e->job;
        e->job=NULL; 
        while(job && job->fentry == e ) {
                Job *prev=job;
                job=job->next;
                ret+=free_job(prev); 
                scans.jobs--;
        }
        pthread_mutex_unlock(&mut);
        return ret;
}

void start_job_threads(int job_threads) {
        pthread_t threads[job_threads];
        for(int i=0; i<job_threads; i++) {
                if (pthread_create(&threads[i],NULL,job_queue_loop,NULL)<0) {
	                perror("thread_create");
	                exit(1);
                }
        }
}

