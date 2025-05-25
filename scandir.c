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
        assert(dir->magick==0xDADDAD);

        /* Check if the parent to be freed */
        pthread_mutex_lock(&mut);
        pthread_mutex_unlock(&mut);


    scans.dirs_active--;
    dir->magick=0xDADDEAD;
    if (dir->handle>=0) closedir(dir->handle);
    while(dir->entries>0) {
	dir->entries--;
	free(dir->array[dir->entries].name);
	if (dir->array[dir->entries].link) free(dir->array[dir->entries].link);
    }
    free(dir->array);

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
}

/* Initialize a Directory entry, with fstatat() */
Entry *init_entry(Entry * entry, int dfd, char *name) {
        memset(entry,0,sizeof (* entry));

	if (fstatat(dfd, name, &entry->stat, AT_SYMLINK_NOFOLLOW)<0) {
                entry->error=errno;
	        show_error("fstatat",name);
	} else if (S_ISLNK(entry->stat.st_mode)) {
	    /* Read the symlink if there is one. FIXME: maybe skip this if we don't have --preserve-links */
	    char linkbuf[MAXLEN];
	    int link_len;

	    if ( (link_len=readlinkat(dfd, name, linkbuf, sizeof(linkbuf)-1))<=0 ||
		 (entry->link=malloc(link_len+1))==NULL ) {
		/* Failed to read link. */
		show_error("readlink",name);
		/* FIXME: read errors is not visible here: 
                opers.read_errors++; */
	    } else {
		/* Save the link */
		memcpy(entry->link, linkbuf, link_len);
		entry->link[link_len]=0;
	    }
	}
        entry->name=name;
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
    nd->name=strdup(name);
    nd->handle=d;
    nd->refs=0;
    if (nd->parent) nd->parent->refs++;

    /* scan the directory */
    while( (dent=readdir(d)) ) {
	if (entries==allocated) {
	    /* Needreu more space */
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

    nd->array=malloc(entries * sizeof(Entry));
    if (!nd->array) goto fail;
    nd->entries=entries;

    /* Initialize all entries in a directory  */
    for (i=0;i<nd->entries;i++) {
	assert(i==0 || my_strcmp(&names[i-1],&names[i])<0);
        init_entry(&nd->array[i], dfd, names[i]);
    }

    /* Names is no longer needed */
    free(names);
    scans.dirs_scanned++;
    if (++scans.dirs_active > scans.dirs_active_max) scans.dirs_active_max=scans.dirs_active;

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
        free(job);
        return ret;
}

/* Threaded directory scan:
 * - if we know nothing of the directory or it is waiting in queue scan it in this thread.
 * - If it is already being scanned by another thread, wait for it. 
 * - If it has been already scanned by another thread use the result. 
 * - Launch directory scan jobs for subdirectories found.
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
                        if (d->from==parent && strcmp(d->fentry->name,basename) ==0 ) break;
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
                        if ( (d=calloc(sizeof(*d),1)) == NULL ) {
                                perror("malloc");
                                exit(1);
                        }
                        d->fentry=&result->array[i];
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
        assert(job->from);
        job->ret=job->callback(job->from,job->fentry,job->to,job->target,job->offset);
        pthread_mutex_lock(&mut);
        job->state=JOB_READY;
        return job;
}

/* Runs one job: can be called by a thread when waiting jobs to finish.
 * Assumes mutex is held.
 * Try to held the job queue shorter by running scan jobs first. 
 */
 int run_one_job() {
        Job *j=pre_scan_list;
        while(j && j->state != SCAN_WAITING) j=j->next;
        if (j) {
                 j->state=SCAN_RUNNING;
                pthread_mutex_unlock(&mut);
                j->result=scan_directory(j->fentry->name,j->from);
                /* Don't keep prescanned directories open. */
                if (j->result) {
                        if (j->result->handle) closedir(j->result->handle);
                        j->result->handle=NULL;
                }
                pthread_mutex_lock(&mut);
                j->state=SCAN_READY;
                pthread_cond_broadcast(&cond);
                return 1;
        }

        for(j=pre_scan_list;j && j->state!=JOB_WAITING; j=j->next);
        if(j) {
                run_job(j);
                j=pre_scan_list;
                pthread_cond_broadcast(&cond);
                return 1;
        }
        return 0;

 }

/* Threads wait in this loop for jobs to run */
void *job_queue_loop(void *arg) {

        pthread_mutex_lock(&mut);
        /* Loop until exit() is called*/
        while(1) {
                if (!run_one_job()) {
                        /* No jobs to run. Wait for something to come to the queue */
                        pthread_cond_wait(&cond,&mut);
                        continue;
                }
        }

    /* Never return */
}

Job *submit_job(Directory *from, Entry *fentry, Directory *to, const char *target, off_t offset, JobCallback *callback) {
        assert(from);
        Job *job=calloc( sizeof (Job), 1);
        if (!job) {
                perror("calloc");
                exit(1);
        }
        job->from=from;
        job->fentry=fentry;
        job->to=to;
        job->target=target;
        job->offset=offset;
        job->callback=callback;
        job->state=JOB_WAITING;

        pthread_mutex_lock(&mut);
	job->next=pre_scan_list;
	pre_scan_list=job;
        if ( ++scans.jobs > scans.maxjobs ) scans.maxjobs=scans.jobs;
        pthread_mutex_unlock(&mut); 
        pthread_cond_broadcast(&cond);

        return job;
}

int wait_for_job(Job *job) {
       assert(job);
       pthread_mutex_lock(&mut);
       while(job->state!=JOB_READY) {
                if (job->state==JOB_RUNNING) {
                        /* We wait, but we could just as well run some job */
                        if (!run_one_job()) {
                                // Nothing to run. We have to wait.
		                pthread_cond_broadcast(&cond);
		                pthread_cond_wait(&cond,&mut);
                        }
                }
                if (job->state==JOB_WAITING) {
                        run_job(job); // Run it ourselves
                }
        }
        int ret=free_job(job);
        scans.jobs--;
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

