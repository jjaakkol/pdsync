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
    char *source;
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

    /* Assume that the parent has not freed yet by other threads. */
    assert(!parent || parent->magick==0xDADDAD);

     /* TODO: should the O_NOATIME be a flag*/
    dfd=openat( (parent) ? dirfd(parent->handle) : AT_FDCWD , name, O_NOFOLLOW|O_RDONLY|O_DIRECTORY);
    if (dfd<0) {
        show_error("openat",name);
        return NULL;
    }
    d=fdopendir(dfd);
    if (!d) {
        show_error("fdopenbdir", name);
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
    nd->handle=d;

    /* scan the directory */
    while( (dent=readdir(d)) ) {
	if (entries==allocated) {
	    /* Need more space */
	    char **tmp_names=NULL;
	    
	    allocated+=allocated/2;
	    tmp_names=realloc(names,sizeof(char *)*allocated);
	    if (!tmp_names) goto fail;
	    names=tmp_names;	    
	}
	if (dent->d_name[0]=='.') {
	    /* Skip '.' and '..' */
	    if (dent->d_name[1]==0) continue; 
	    if (dent->d_name[1]=='.' && dent->d_name[2]==0) continue;
	}
	if ( (names[entries]=strdup(dent->d_name))==NULL ) goto fail;
	entries++;
    } 

    /* TODO: maybe stat the directories first, then sort them */
    /* Sort the directory entries */
    qsort(names,entries,sizeof(names[0]),my_strcmp);    

    nd->array=calloc(entries,sizeof(Entry));
    if (!nd->array) goto fail;
    nd->entries=entries;

    /* Stat all entries */
    for (i=0;i<nd->entries;i++) {
	assert(i==0 || my_strcmp(&names[i-1],&names[i])<0);

        nd->array[i].state=ENTRY_GOOD;
	if (fstatat(dfd, names[i],&nd->array[i].stat, AT_SYMLINK_NOFOLLOW)<0) {
	    show_error("scan_directory lstat",names[i]);
	    /* Mark the files which cannot be stat:ed */
	    nd->array[i].state=ENTRY_STAT_FAILED;
	} else if (S_ISLNK(nd->array[i].stat.st_mode)) {
	    /* Read the link */
	    char linkbuf[MAXLEN];
	    int link_len;

	    if ( (link_len=readlinkat(dfd,names[i],linkbuf,sizeof(linkbuf)-1))<=0 ||
		 (nd->array[i].link=malloc(link_len+1))==NULL ) {
		/* Failed to read link. */
		show_error("readlink",names[i]);
		/* FIXME: read errors is not vible here: 
                opers.read_errors++; */
		nd->array[i].link=NULL;
		nd->array[i].state=ENTRY_READLINK_FAILED;
	    } else {
		/* Save the link */
		memcpy(nd->array[i].link,linkbuf,link_len);
		nd->array[i].link[link_len]=0;
	    }
	}
	nd->array[i].name=names[i];
        scans.entries_scanned++;
    }

    /* Names is no longer needed */
    free(names);
    scans.dirs_scanned++;

    nd->magick=0xDADDAD;
    return nd;

    fail:
    /* Something did not work out. Clean up */
    if (nd) {
	int i;
	for(i=0;i<nd->entries;i++) {
	    if (nd->array[i].link) free(nd->array[i].link);
	}
	if (nd->array) free(nd->array);
	free(nd);
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
        if (job==pre_scan_list) pre_scan_list=job->next;
        else {
                Job *prev=pre_scan_list;
                while (prev->next != job) prev=prev->next;
                prev->next=job->next;
        }
        int ret=job->ret;
        job->next=NULL;
        job->state=JOB_INVALID;
	free(job->source);
        //free(job->target);
        free(job);
        return ret;
}

/* Threaded directory scan:
 * - if we know nothing of the directory or it is waiting in queue scan it in this thread.
 * - If it is already being scanned by another thread, wait for it. 
 * - If it has been already scanned by another thread use the result. 
 * - Launch directory scan jobs for subdirectories found.ACCESSPERMS
 */
Directory *pre_scan_directory(const char *path, Directory *parent) {
        Job *d=NULL;
        Directory *result=NULL;
        const char *basename=NULL;
        int i;

        /* Lock the list */
        pthread_mutex_lock(&mut);

        /* The prescanner only knows the parent and the last compotent of the dir name */
        basename=path;
        for (i=0; path[i]; i++) {
                if (path[i]=='/') basename=path+i+1;
        }
        assert(basename[0]!='\0' && basename[0]!='/');

        /* Loop over the job queue to find matching scan job if any */
        for (d=pre_scan_list; d; d=d->next) {
                // printf("pre_scan %s %s\n",dir,d->dir);
                assert(d->state!=JOB_INVALID);

                if (d->state==SCAN_WAITING || d->state==SCAN_RUNNING || d->state==SCAN_READY) {
                        if (d->from==parent && strcmp(d->source,basename) ==0 ) break;
                }
        }

        if (d) {
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
                free_job(d);
                d=NULL;
	        scans.pre_scan_used++;
        }    

        pthread_mutex_unlock(&mut); /* Do not lock the critical section during IO or scan_directory*/

        /* Reopen the DIR * handle of prescanned directories. */
        if (result && result->handle==NULL) {
                assert(result->parent && result->parent->magick==0xDADDAD && result->parent->handle);
                int dfd=openat(dirfd(result->parent->handle),basename,O_DIRECTORY|O_RDONLY|O_NOFOLLOW);
                struct stat dirstat,parentstat;
                if (dfd<0 || 
                        fstatat(dfd,"..",&dirstat,AT_SYMLINK_NOFOLLOW)<0 || 
                        fstat(dirfd(result->parent->handle),&parentstat)<0 ||
                        dirstat.st_dev!=parentstat.st_dev || dirstat.st_ino != parentstat.st_ino) {
                        show_error("directory has changed.",path);
                        d_freedir(result);
                        return NULL;
                }
                result->handle=fdopendir(dfd);
                assert(result->handle);
        } else {
	        /* The directory was not in queue or was not started. Scan it in this thread*/
	        scans.pre_scan_misses++;
                // printf("Miss: %s %s\n",path,basename);
	        result=scan_directory(path,parent);
        }

        pthread_mutex_lock(&mut); /* Need mutex to add new jobs */
   
        if (result==NULL) goto out;

        /* Now add the newly found directories to the job queue for prescanning*/
        for(i=result->entries-1; i>=0; i--) {
	        if (S_ISDIR(result->array[i].stat.st_mode)) {
                        if ( (d=calloc(sizeof(*d),1)) == NULL  || 
                                (d->source=strdup(result->array[i].name)) == NULL ) {
                                perror("malloc");
                                exit(1);
                        }
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

/* This is caalled with the mutex held */
Job *run_job(Job *job) {
        assert(job->state==JOB_WAITING && job->callback);
        job->state=JOB_RUNNING;
        pthread_mutex_unlock(&mut);
        job->ret=job->callback(job->from,job->source,job->to,job->target,job->offset);
        pthread_mutex_lock(&mut);
        job->state=JOB_READY;
        return job;
}

/* Threads wait in this loop for jobs to run */
void *job_queue_loop(void *arg) {
        Job *d=pre_scan_list;

        pthread_mutex_lock(&mut);
        /* Loop until exit() is called*/
        while(1) {
                if (!d) {
                        /* No jobs to run. Wait for something to come to the queue */
                        pthread_cond_wait(&cond,&mut);
                        d=pre_scan_list;
                        continue;
                }

	        /* Try to find a job to run */
                switch (d->state) {
                case SCAN_WAITING:
                        d->state=SCAN_RUNNING;
                        pthread_mutex_unlock(&mut);
                        d->result=scan_directory(d->source,d->from);
                        /* Don't keep prescanned directories open. */
                        if (d->result->handle) closedir(d->result->handle);
                        d->result->handle=NULL;
                        pthread_mutex_lock(&mut);
                        d->state=SCAN_READY;
                        d=pre_scan_list;
                        pthread_cond_broadcast(&cond);
                        break;
                case JOB_WAITING:
                        run_job(d);
                        d=pre_scan_list;
                        pthread_cond_broadcast(&cond);
                        break;
                default:
                        d=d->next;
                }

        }

    /* Never return */
}

Job *submit_job(Directory *from, const char *source, Directory *to, const char *target, off_t offset, JobCallback *callback) {
        Job *job=calloc( sizeof (Job), 1);
        if (!job) {
                perror("calloc");
                exit(1);
        }
        job->from=from;
        job->source=(source) ? strdup(source) : NULL;
        job->to=to;
        job->target=target;
        job->offset=offset;
        job->callback=callback;
        job->state=JOB_WAITING;
        job->from=NULL;

        pthread_mutex_lock(&mut);
	job->next=pre_scan_list;
	pre_scan_list=job;
        pthread_mutex_unlock(&mut); 
        return job;
}

int wait_for_job(Job *job) {
       pthread_mutex_lock(&mut);
       while(job->state!=JOB_READY) {
                if (job->state==JOB_RUNNING) {
                        /* We wait, but we could just as well run some job */
		        pthread_cond_broadcast(&cond);
		        pthread_cond_wait(&cond,&mut);
                }
                if (job->state==JOB_WAITING) {
                        run_job(job); // Run it ourselves
                }
        }
        int ret=free_job(job);
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
        printf("Started %d threads\n",job_threads);
}

