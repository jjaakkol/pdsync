#include "dsync.h"

typedef enum {
    NOT_STARTED=0,
    SCANNING=1,
    READY=2
} ScanState;

typedef struct PreScanStruct {
    char *dir;
    ScanState state;
    Directory *result;
    struct PreScanStruct *next;
} PreScan;

pthread_mutex_t mut = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
volatile PreScan *pre_scan_list=NULL;
pthread_t pre_reader;

static int my_strcmp(const void *x, const void *y) {
    const char *a=*(const char **)x;
    const char *b=*(const char **)y;
    return strcmp(a,b);
}

/* NOTE: if --pre-scan is used, scan_directory may be called 
 *       from different threads */
Directory *scan_directory(const char *dir) {
    DIR *d=opendir(dir);
    Directory *nd=NULL;
    struct dirent *dent;
    int i;
    int allocated=16;
    int entries=0;
    char **names=NULL;
    char scdir[MAXLEN];

    if (!d) return NULL;
    if ( (names=malloc(sizeof(char *)*allocated)) ==NULL) {
	goto fail;
    }

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
    closedir(d);
    
    /* Sort the directory entries */
    qsort(names,entries,sizeof(names[0]),my_strcmp);    

    /* Allocate the Directory structure */
    if ( ! (nd=malloc(sizeof(Directory))) ) {
	goto fail;
    }
    nd->array=malloc(sizeof(Entry)*entries);
    if (!nd->array) goto fail;
    memset(nd->array,0,sizeof(Entry)*entries);
    nd->entries=entries;

    /* Stat the directories */
    for (i=0;i<nd->entries;i++) {
	assert(i==0 || my_strcmp(&names[i-1],&names[i])<=0);
	    
	snprintf(scdir,sizeof(scdir),"%s/%s",dir,names[i]);
	nd->array[i].state=ENTRY_GOOD;
	if (lstat(scdir,&nd->array[i].stat)<0) {
	    show_error("lstat",scdir);
	    /* Mark the files which cannot be stat:ed */
	    nd->array[i].state=ENTRY_STAT_FAILED;
	} else if (S_ISLNK(nd->array[i].stat.st_mode)) {
	    /* Read the link */
	    char linkbuf[MAXLEN];
	    int link_len;

	    if ( (link_len=readlink(scdir,linkbuf,sizeof(linkbuf)-1))<=0 ||
		 (nd->array[i].link=malloc(link_len+1))==NULL ) {
		/* Failed to read link. */
		show_error("readlink",scdir);
		/* opers.read_errors++; */
		nd->array[i].link=NULL;
		nd->array[i].state=ENTRY_READLINK_FAILED;
	    } else {
		/* Save the link */
		memcpy(nd->array[i].link,linkbuf,link_len);
		nd->array[i].link[link_len]=0;
	    }
	}
	nd->array[i].name=names[i];	
    }

    /* Names is no longer needed */
    free(names);

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

Directory *pre_scan_directory(const char *dir) {
    PreScan *d=NULL;
    PreScan *prev=NULL;
    Directory *result=NULL;
    int i;

    /* Lock the list */
    pthread_mutex_lock(&mut);

    /* Check if we allready have the dir in scanlist */
    d=pre_scan_list;
    while(d && strcmp(d->dir,dir)!=0) {
	prev=d;
	d=d->next;
    }

    if (d) {
	/* We had it in the list */
	switch(d->state) {
	case NOT_STARTED:
	    /* Do it our selves */
	    d->state=SCANNING;
	    scans.pre_scan_misses++;
	    pthread_mutex_unlock(&mut);
	    d->result=scan_directory(dir);
	    pthread_mutex_lock(&mut);
	    break;
	case SCANNING:
	    /* Already started. Wait for finish */
	    scans.pre_scan_wait_hits++;
	    /* Wait until the reader has read it */
	    while(d->state!=READY) {
		pthread_cond_broadcast(&cond);
		pthread_cond_wait(&cond,&mut);
	    }
	    break;
	case READY:
	    /* It was ready */
	    scans.pre_scan_hits++;
	    break;
	}
	/* Now we can remove it from the list */
	if (prev) {
	    prev->next=d->next;
	} else {
	    pre_scan_list=d->next;
	}
	result=d->result; /* Might be NULL in case of error */
	free(d->dir);
	free(d);
	d=NULL;
	scans.pre_scan_used++;
    } else {
	/* We did not have it in the list. Do the old fashion way */
	scans.pre_scan_misses++;
	result=scan_directory(dir);
    }

    if (result==NULL) goto out;

    /* Now add the newly found directories to scan list */
    for(i=result->entries-1; i>=0; i--) {
	if (S_ISDIR(result->array[i].stat.st_mode)) {
	    /* Found a directory to prescan */
	    size_t len=strlen(dir)+strlen(result->array[i].name)+2;	
	    if ( (d=malloc(sizeof(PreScan)))==NULL ||
		 (d->dir=malloc(len))==NULL ) {
		perror("malloc");
		exit(1);
	    }
	    snprintf(d->dir,len,"%s/%s",dir,result->array[i].name);
	    d->result=NULL;
	    d->state=NOT_STARTED;
	    d->next=pre_scan_list;	    
	    pre_scan_list=d;
	    scans.pre_scan_allocated++;
	}
    }
    
    if (pre_scan_list) {
	/* Kick the scanner thread */
	pthread_cond_broadcast(&cond);
    }

 out:
    pthread_mutex_unlock(&mut);
    return result;
}

void *pre_read_loop(void *arg) {
    pthread_mutex_lock(&mut);
    while(1) {
	PreScan *d=NULL;
	int i=0;
	
	/* Try to find something to scan */
	d=pre_scan_list;
	while(d && d->state!=NOT_STARTED && i<5) {
	    d=d->next;
	    i++;
	}
	
	if ( (d==NULL) || d->state!=NOT_STARTED) {
	    /* Did not find anything. Wait for something new. */
	    /* printf("Pre_scanner waiting\n"); */
	    pthread_cond_wait(&cond,&mut);
	} else {
	    /* Found a directory to scan */
	    d->state=SCANNING;
	    /* printf("pre_scanner scanning %s\n",d->dir); */
	    pthread_mutex_unlock(&mut);
	    d->result=scan_directory(d->dir);
	    pthread_mutex_lock(&mut);
	    d->state=READY;
	    scans.pre_scan_dirs++;
	    pthread_cond_broadcast(&cond);
	}
    }
    return NULL; /* Never */
}

void start_pre_scan_thread() {
    if (pthread_create(&pre_reader,NULL,pre_read_loop,NULL)<0) {
	perror("thread_create");
	exit(1);
    }
}
