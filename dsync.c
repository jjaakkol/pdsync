#include "dsync.h"

#ifndef O_NOFOLLOW
#warning "O_NOFOLLOW is not defined"
#define O_NOFOLLOW 0
#endif

#define VERSION "1.11"

static int dryrun=0;
static int delete=0;
static int delete_only=0;
static int one_file_system=0;
static int atime_preserve=0;
static int verbose=0;
static int quiet=0;
static int preserve_permissions=0;
static int preserve_owner=0;
static int preserve_group=0;
static int preserve_time=0;
static int preserve_devices=0;
static int preserve_links=0;
static int preserve_sparse=0;
static int preserve_hard_links=0;
static int recursive=0;
static int safe_mode=0;
static int update_all=0;
static int show_warnings=1;
static int privacy=0;
static int progress=0;
static int threads=4;
uid_t myuid=0;

FILE *tty_stream=NULL; /* For --progress */

size_t target_dir_len=1024, source_dir_len=1024;
static const char *target_dir=NULL;

typedef struct ExcludeStruct {
    regex_t regex;
    struct ExcludeStruct *next;
} Exclude;
    
Exclude *exclude_list=NULL;
Exclude **last_excluded=&exclude_list;

    
        
static char s_topath[MAXLEN];
static char s_frompath[MAXLEN];

static struct stat target_stat;
static struct stat source_stat;

typedef struct {
    int dirs_created;
    int files_copied;
    int entries_removed;
    int dirs_removed;
    long long bytes_copied;
    long long sparse_bytes;
    int symlinks_created;
    int sockets_created;
    int fifos_created;
    int devs_created;
    int hard_links_created;
    int read_errors;
    int write_errors;
    int no_space;
    int chown;
    int chmod;
    int times;
} Opers; 
Opers opers;
Scans scans;

typedef struct LinkStruct {
    dev_t source_dev;
    ino_t source_ino;
    dev_t target_dev;
    ino_t target_ino;
    char *target_name;
    struct LinkStruct *next;
} Link;

static Link **link_htable=NULL;
static int hash_size=1009;

enum { ATIME_PRESERVE=255, PRIVACY=256, DELETE_ONLY=257,
       THREADS=258
};

static struct option options[]= {
    { "dry-run",         0, NULL, 'n' },
    { "verbose",         0, NULL, 'v' },
    { "progress",        0, NULL, 'P' },
    { "version",         0, NULL, 'V' },
    { "help",            0, NULL, 'h' },
    { "one-file-system", 0, NULL, 'x' },
    { "quiet",           0, NULL, 'q' },
    { "delete",          0, NULL, 'd' },
    { "archive",         0, NULL, 'a' },
    { "links",           0, NULL, 'l' },
    { "perms",           0, NULL, 'p' },
    { "owner",           0, NULL, 'o' },
    { "group",           0, NULL, 'g' },
    { "devices",         0, NULL, 'D' },
    { "times",           0, NULL, 't' },
    { "recursive",       0, NULL, 'r' },
    { "update-all",      0, NULL, 'U' },
    { "sparse",          0, NULL, 'S' },
    { "hard-links",      0, NULL, 'H' },
    { "exclude-regex",   1, NULL, 'X' },
    { "atimes",          0, NULL, ATIME_PRESERVE },
    { "privacy",         0, NULL, PRIVACY },
    { "delete-only",     0, NULL, DELETE_ONLY },
    { "threads",         1, NULL, THREADS },
    { NULL, 0, NULL, 0 }       
};

static void show_version() {
    printf("dsync "VERSION" (C) 09.2000 - 03.2004 Jani Jaakkola (jjaakkol@cs.helsinki.fi)\n");
}

static void show_help() {
    int i;
    int len=0;
    show_version();
    printf("Usage: dsync [options] <fromdir> <todir>\n");
    printf("dsync is a tool for synchronization of two local directories.\n");
    printf("Options are:\n");
    for(i=0;options[i].name;i++) {
	while((len>0 && len<26) || (len>26 && len<52)) {
	    putchar(' '); len++;
	}
	if (len>52) { putchar('\n'); len=0; }
	if (options[i].val<255) {
	    len+=printf(" -%c --%s",options[i].val, options[i].name);
	} else {
	    len+=printf("    --%s",options[i].name);
	}
    }    
    putchar('\n');
}


void show_error(const char *why, const char *file) {
    if (errno==ENOSPC) {
	opers.no_space++;
    }
    fprintf(stderr,"Error: %s %s: %s\n",why,
	    (privacy) ? "[PRIVATE]":file,
	    (errno==0) ? "" : strerror(errno));
}

static void show_error2(const char *why, const char *path, const char *file) {
    if (errno==ENOSPC) {
	opers.no_space++;
    }
    if (privacy) {
	fprintf(stderr,"Error: %s [PRIVATE]: %s\n",why,
		(errno==0) ? "" : strerror(errno));
    } else {
	fprintf(stderr,"Error: %s %s/%s: %s\n",why,
		path,file,
		(errno==0) ? "" : strerror(errno));
    }
}

static void show_warning(const char *why, const char *file) {
    if (show_warnings) {
	if (file) {
	    fprintf(stderr,"Warning: %s: %s\n",why,
		    (privacy) ? "[PRIVATE]":file);
	} else {
	    fprintf(stderr,"Warning: %s\n",why);
	}
    }
}

/* Dumps recursively the path from EntryPath obeying privacy */
#if 0 /* FIXME: EntryPath is gone and we have Directory */
static int write_path(FILE *f, const EntryPath *path, const Entry *current) {
    int p=0;
    if (path) p=write_path(f,path->parent,path->entry);
    
    if (p) fprintf(f,"[x]");
    else fprintf(f,"%s",current->name);
    if (S_ISDIR(current->stat.st_mode)) fputc('/',f);

    return p || (privacy && 
		 current->stat.st_uid!=myuid &&
		 !(current->stat.st_mode & S_IROTH));    
}
#endif 

/* Shows the progress, obeying privacy options */
static void show_progress(const char *str) {
    static int last_scanned=0;
    static long long last_bytes;
    static long long last=0;
    struct timeval tv;

    if (!progress) return;

    /* Once a second */    
    gettimeofday(&tv,NULL);
    long long now=tv.tv_sec*1000000 + tv.tv_usec;
    if (now-last < 1000000) return;

    fprintf(tty_stream,"PG: %7d files, %lld files/s, %lld MiB, %lld MiB/s, %d jobs: %s\n",
        scans.entries_scanned,
        1000000LL * (scans.entries_scanned-last_scanned) / (now-last),
        opers.bytes_copied / (1024*1024),
        1000000LL * (opers.bytes_copied-last_bytes) / (now-last) / (1024*1024),
        scans.jobs,
        str
    );
    last_scanned=scans.entries_scanned;
    last_bytes=opers.bytes_copied;
    last=now;
}

	
static int parse_options(int argc, char *argv[]) {
    int opt;
    int i;

    char ostr[128]="";
    int j=0;
    for(i=0;options[i].name;i++) {
	if (options[i].val<255) {
	    ostr[j++]=options[i].val;
	    if (options[i].has_arg) ostr[j++]=':';
	}
    }
    ostr[j]=0;
    while( (opt=getopt_long(argc, argv, ostr, options, NULL))>=0 ) {
	switch(opt) {
	case 'n': dryrun=1; break;
	case 'v': verbose++; break;
	case 'P': 
	    tty_stream=fopen("/dev/tty","w");
	    if (!tty_stream) {
		fprintf(stderr,"Could not open /dev/tty. Using stdout for progress reports.\n");
		tty_stream=stderr;
	    }	    
	    progress++; 
	    break;
	case 'V': show_version(); exit(0);
	case 'h': show_help(); exit(0);
	case 'q': quiet++; break;
	case 'd': delete=1; break;
	case 'r': recursive=1; break;
	case 'l': preserve_links=1; break;
	case 'p': preserve_permissions=1; break;
	case 'o': preserve_owner=1; break;
	case 'g': preserve_group=1; break;
	case 't': preserve_time=1; break;
	case 'D': preserve_devices=1; break;	    
	case 'x': one_file_system=1; break;
	case 'U': update_all=1; break;
	case 'S': preserve_sparse=1; break;
	case 'H': preserve_hard_links=1; break;
	case ATIME_PRESERVE: atime_preserve=1; break;
	case PRIVACY: privacy=1; break;
	case DELETE_ONLY: delete=1; delete_only=1; break;
	case THREADS: {
                        char *endptr=NULL;
                        threads=strtol(optarg,&endptr,10);
                        if (!optarg[0] || *endptr || threads<0 || threads > 256 ) {
                                fprintf(stderr,"Invalid value given to --threads: '%s'\n",optarg);
                                exit(1);
                        }
                        printf("Using %d threads\n",threads);
                        break;
                }
	case 'a': 
	    recursive=1;
	    preserve_permissions=1;
	    preserve_owner=1;
	    preserve_group=1;
	    preserve_time=1;
	    preserve_devices=1;
	    preserve_links=1;
	    break;
	case 'X': {
	    int error;
	    regex_t *r=NULL;
	    *last_excluded=malloc(sizeof(Exclude));
	    if (!*last_excluded) {
		perror("malloc");
		exit(1);
	    }
	    r=&(*last_excluded)->regex;
	    last_excluded=&(*last_excluded)->next;
	    *last_excluded=NULL;

	    if ((error=regcomp(r,optarg, REG_EXTENDED|REG_NOSUB))<0) {
		char errstr[256];
		regerror(error,r,errstr,sizeof(errstr));
		fprintf(stderr,"Error in --exclude-regex regex '%s': %s\n",
			optarg,errstr);
		exit(1);
	    }
	    break;
	}

	default:
	    fprintf(stderr,"Unknown option '%c'.\n",opt);
	    show_help();
	    exit(1);
	    break;
	}
    }
    return 0;
}

static void print_scans(const Scans *scans) {
    if (scans->dirs_scanned) {
	printf("%8d directories scanned\n",scans->dirs_scanned);
    }
    if (scans->entries_scanned) {
	printf("%8d inodes scanned\n",scans->entries_scanned);
    }
    if (scans->dirs_skipped) {
	printf("%8d directories skipped\n",scans->dirs_skipped);
    }
    if (scans->maxjobs) {
        printf("%8d maximum simultaneous jobs in queue.\n", scans ->maxjobs);
    }
    if (scans->pre_scan_hits) {
	printf("%8d directory prescan hits\n",scans->pre_scan_hits);
    }
    if (scans->pre_scan_wait_hits) {
	printf("%8d directory prescan wait hits\n",scans->pre_scan_wait_hits);
    }
    if (scans->pre_scan_misses) {
	printf("%8d directory prescan misses\n",scans->pre_scan_misses);
    }	
    if (scans->pre_scan_dirs) {
	printf("%8d pre scanned directorys\n",scans->pre_scan_dirs);
    }	
    if (scans->pre_scan_allocated) {
	printf("%8d allocated pre scan entries\n",scans->pre_scan_allocated);
    }	
    if (scans->pre_scan_used!=scans->pre_scan_allocated) {
	printf("%8d unused pre scan entries\n",
	       scans->pre_scan_allocated-scans->pre_scan_used);
    }	
}

static void print_opers(const Opers *stats) {
    if (stats->dirs_created) {
	printf("%8d directories created\n",stats->dirs_created);
    }
    if (stats->dirs_removed) {
	printf("%8d directories removed\n",stats->dirs_removed);
    }
    if (stats->entries_removed) {
	printf("%8d entries removed\n",stats->entries_removed);
    }
    if (stats->files_copied) {
	printf("%8d files copied\n",stats->files_copied);
    }
    if (stats->bytes_copied>100*1024*1024) {
	printf("%8Ld MB data copied\n",stats->bytes_copied/1024/1024);
    } else if (stats->bytes_copied) {
	printf("%8Ld KB data copied\n",stats->bytes_copied/1024);
    }
    if (stats->sparse_bytes>100*1024*1024) {
	printf("%8Ld MB in sparse blocks\n",stats->sparse_bytes/1024/1024);
    } else if (stats->sparse_bytes) {
	printf("%8Ld KB in sparse blocks\n",stats->sparse_bytes/1024);
    }
    if (stats->symlinks_created) {
	printf("%8d symlinks created\n",stats->symlinks_created);
    }
    if (stats->hard_links_created) {
	printf("%8d hard links created\n",stats->hard_links_created);
    }
    if (stats->sockets_created) {
	printf("%8d sockets created\n",stats->sockets_created);
    }
    if (stats->fifos_created) {
	printf("%8d fifos created\n",stats->fifos_created);
    }
    if (stats->devs_created) {
	printf("%8d devs created\n",stats->devs_created);
    }
    if (stats->read_errors) {
	printf("%8d errors on read\n",stats->read_errors);
    }
    if (stats->write_errors) {
	printf("%8d errors on write\n",stats->write_errors);
    }
}

void d_freedir(Directory *dir) {
    assert(dir->magick==0xDADDAD);
    dir->magick=0xDADDEAD;
    if (dir->handle>=0) closedir(dir->handle);
    while(dir->entries>0) {
	dir->entries--;
	free(dir->array[dir->entries].name);
	if (dir->array[dir->entries].link) free(dir->array[dir->entries].link);
    }
    free(dir->array);
    dir->entries=-123; /* Magic value to debug a race */
    free(dir);
}

int remove_hierarchy(const char *dir, Directory *parent) {
    struct stat thisdir;
    Directory *del=NULL;
    int i;
    int skip_rmdir=0;
    int dfd=-1;
 
    del=pre_scan_directory(dir,parent);
    if (!del) {
	show_error("remove directory","PATHMISSING");
	return -1;
    }
    dfd=dirfd(del->handle);
    fstat(dfd,&thisdir);
    if (thisdir.st_dev==source_stat.st_dev &&
	thisdir.st_ino==source_stat.st_ino) {
	/* This can happen when doing something like 
	 * dsync /tmp/foo/bar /tmp/foo */
	show_warning("Skipping removal of source directory","PATHMISSING");
	goto fail;
    }
    if (thisdir.st_dev==target_stat.st_dev &&
	thisdir.st_ino==target_stat.st_ino) {
	/* This should only happen on badly screwed up filesystems */
	show_warning("Skipping removal of target directory (broken filesystem?).\n","PATHMISSING");
	goto fail;
    }
  
    for(i=0;i<del->entries;i++) {
	struct stat file;
	if (fstatat(dfd,del->array[i].name,&file,AT_SYMLINK_NOFOLLOW)<0) {
	    show_error2("fstatat","PATHMISSING",del->array[i].name);
	    goto fail;
	}
	if (S_ISDIR(file.st_mode)) {
	    int r;
	    r=remove_hierarchy(del->array[i].name,del);
	    if (r<0) goto fail;
	} else {
	    if (!dryrun && unlinkat(dfd,del->array[i].name,0)<0) {
		show_error2("unlinkat","PATHMISSING",del->array[i].name);
		/* FIXME: maybe continue here? */
		goto fail;
	    } else {
                if (verbose) {
		  printf("RM: %s/%s\n","PATHMISSING",del->array[i].name);
	        }
		opers.entries_removed++;
	    }
	}
    }

 cleanup:
    if (del) d_freedir(del);
    if (verbose && !skip_rmdir) {
	printf("RD: %s/%s\n","PATHMISSING",dir);
    }
    if (!dryrun && !skip_rmdir && unlinkat(dirfd(parent->handle),dir,AT_REMOVEDIR)<0) {
	show_error2("rmdir","PATHMISSING",dir);
	opers.write_errors++;
        return -1;
    } else {
	opers.dirs_removed++;
    }
    return 0;

 fail:
    skip_rmdir=1;
    opers.write_errors++;
    goto cleanup;
}    

int copy_regular(Directory *from,
		 const char *source, 
		 Directory *to,
		 const char *target,
                 off_t offset) {
        int fromfd=-1;
        int tofd=-1;
        struct stat from_stat;
        int sparse_copy=0;
        int ret=0;
        off_t copy_job_size=128*1024*1024;
        Job **jobs=NULL;
        int num_jobs=0;

        assert(from && source && to && target);

        fromfd=openat(dirfd(from->handle),source,O_RDONLY|O_NOFOLLOW);
        if (fromfd<0 || fstat(fromfd,&from_stat)) {
	        show_error2("open","NOPATH",source);
	        goto fail;
        }
        /* offset -1 means that this is the first job operating on this file */
        if (offset==-1) {
                if (verbose) {
                        printf("CP: %s\n",target);       
                }
                /* Check for sparse file */
                if ( from_stat.st_size > (1024*1024) && from_stat.st_size/512 > from_stat.st_blocks ) {
	                static int sparse_warned=0;
	                if (!sparse_warned && !preserve_sparse) {
	                        show_warning("Sparse or compressed files detected. Consider --sparse option",source);
                                sparse_warned++;
                        }
	        }
	        sparse_copy=preserve_sparse;
                if (dryrun) {
                        opers.files_copied++;
	                opers.bytes_copied+=from_stat.st_size;
                        close(fromfd);
                        return 0;
                }

                /* Start the other copy threads from the first thread */
                num_jobs=from_stat.st_size/copy_job_size;
                jobs=calloc( sizeof(Job *),num_jobs);
                for (int i=num_jobs-1; i>=0; i--) {
                        jobs[i]=submit_job(from,source,to,target,copy_job_size*i,copy_regular);
                }
                int failed_jobs=0;
                for (int i=0; i<num_jobs; i++) {
                        assert(jobs[i]);
                        if (wait_for_job(jobs[i])!=0) failed_jobs++;
                }
                free(jobs);
                if (failed_jobs) fprintf(stderr,"%d failed copy jobs for %s",failed_jobs,target);
                /* Let this thread copy the last bits */
                offset=num_jobs*copy_job_size;

    }

    tofd=openat(dirfd(to->handle),target,O_WRONLY|O_CREAT|O_NOFOLLOW,0666);
    if(tofd<0) {
	show_error("open",target);
	opers.write_errors++;
	goto fail;
    }
	    
    if (sparse_copy) {
	/* Copy loop which handles sparse blocks */
	char *spbuf=NULL;
	int bsize=4096; // 4096 is the default size of many fs blocks
        int r;

	spbuf=malloc(bsize);
        if (!spbuf) {
            perror("malloc");
	    goto fail;
        }
	
        /* Read and skip blocks with only zeros */
	while( (r=read(fromfd,spbuf,bsize)) > 0 ) {
	    int written=0;
	    while(written<r && spbuf[written]==0) written++;
	    if (written==bsize) {
		/* Found a block of zeros */
		if (lseek(tofd,bsize,SEEK_CUR)<0) {
		    perror("lseek");
		    opers.write_errors++;
		    goto fail;
		}
		opers.sparse_bytes+=written;
	    } else {
		written=0;
	    }
	    while (written<r) {
		int w=write(tofd,spbuf+written,r-written);
		if (w<0) {
		    show_error("write",target);
		    opers.write_errors++;
		    goto fail;
		}
		written+=w;
		opers.bytes_copied+=w;
	    }
	}
	free(spbuf);
        if (r<0) {
                show_error("read",source);
                goto fail;
        }
	
    } else {
	/* Simple loop with no regard to filesystem block size or sparse blocks*/
        int w=0;
        if ( lseek(fromfd,offset,SEEK_SET)<0 || lseek(tofd,offset,SEEK_SET)<0 ) {
                show_error("lseek",target);
                goto fail;
        }
        off_t towrite=copy_job_size;
        while(towrite>0 && (w=sendfile(tofd,fromfd,NULL,towrite))>0) {
                opers.bytes_copied+=w;
                towrite-=w;
                show_progress("Copying a file.");
        }
	if (w<0) {
		show_error("write",target);
		opers.write_errors++;
		goto fail;
	}
    }

    opers.files_copied++;

 end:
    if (fromfd>=0) {
	close(fromfd);    
    }
    if (tofd>=0) close(tofd);
    return ret;

 fail:
    ret= -1;
    goto end;
}

int create_target(Directory *from,
                  const char *source,
                  Directory *to,
                  const char *target,
		  const Entry *fentry) {
    assert(from && source && to && target && fentry);
    int tofd=dirfd(to->handle);

    if (S_ISREG(fentry->stat.st_mode)) {
	/* Regular file: copy it */
	if (copy_regular(from,source,to,target,-1)<0) {
	    return -1; // Copy failed
	}

    } else if (S_ISDIR(fentry->stat.st_mode)) {
	/* Directory: create the target directory.
	 * We will be here regardless of whether the directory already 
	 * existed or not. So we test it. */
	struct stat tmp;
	if (!recursive) return -1;
	if (fstatat(tofd,target,&tmp,0)<0) {
	    if (verbose) printf("MD: %s\n",target);
	    if (!dryrun && mkdirat(tofd,target,0777)<0 ) {
		show_error("mkdir",target);
		goto fail;
	    }
	    opers.dirs_created++;
	} else if (!dryrun) {
	    if (!S_ISDIR(tmp.st_mode)) {
		errno=0;
		show_error("Target is not a directory",target);
		goto fail;
	    }
	    if (safe_mode) {
		if (preserve_owner && fchown(tofd,0,0)<0) {
		    show_error("fchown",target);
		    goto fail;
		}
		if (fchmod(tofd,0700)<0) {
		    show_error("chmod",target);
		    goto fail;
		}
	    }
	}

    } else if (S_ISLNK(fentry->stat.st_mode)) {
	/* Create symbolic link */
	if (!preserve_links) return 0;
	if (verbose) printf("SL: %s\n",target);
	if (!dryrun && symlinkat(fentry->link,tofd,target)<0) {
	    /* Symlink failed */
	    show_error("symlink",target);
	    goto fail;
	} else {
	    opers.symlinks_created++;
	}

        // Maybe don't even create sockets?
#if 0

    } else if (S_ISSOCK(fentry->stat.st_mode)) {
	/* Create a socket */
	/* FIXME: hack around UNIX_PATH_MAX */
	if (!preserve_devices) return -1;
	if (verbose) {
	    printf("SO: %s\n",todir);
	}
	if (!dryrun) {
	    int s=socket(PF_UNIX,SOCK_STREAM,0);
	    struct sockaddr_un addr;
	    if (s<0) {
		show_error("socket",todir);
		goto fail;
	    }
	    memset(&addr,0,sizeof(addr));
	    addr.sun_family=AF_UNIX;
	    strncpy(addr.sun_path,todir,sizeof(addr.sun_path)-1);
	    if (bind(s,&addr,sizeof(addr))<0) {
		show_error("bind (socket creation errors ignored)",todir);
	    } else {
		opers.sockets_created++;
	    }
	    close(s);
	}
#endif	    

    } else if (S_ISFIFO(fentry->stat.st_mode)) {
	/* Create a FIFO */
	if (!preserve_devices) return -1;
	if (verbose) {
	    printf("FI: %s\n",target);
	}
	if (!dryrun && mkfifoat(tofd,target,0777)<0) {
	    show_error("mkfifo",target);
	    goto fail;
	}
	opers.fifos_created++;

        // Don't bother when device special files 
#if 0
    } else if (S_ISCHR(fentry->stat.st_mode) ||
	S_ISBLK(fentry->stat.st_mode) ) {
	/* Create a inode device */
	if (!preserve_devices) return -1;
	if (verbose) {
	    printf("DE: %s\n",todir);
	}
	if (!dryrun && 
	    mknod(todir,fentry->stat.st_mode,fentry->stat.st_rdev)<0) {
	    show_error("mknod",todir);
	    goto fail;
	}
	opers.devs_created++;
#endif

    } else {
	if (verbose) printf("UN: %s\n",source);
	show_warning("Unknown file type ignored",source);
    }   
    return 0;

 fail:
    opers.write_errors++;
    return -1;
}

/* Remove one entry from a directory */
int remove_entry(const char *name, Directory *parent, const struct stat *stat) {
        if (S_ISDIR(stat->st_mode)) {
                remove_hierarchy(name,parent);
        } else {
                if (verbose) printf("RM: %s\n",name);
                if (!dryrun && unlinkat(dirfd(parent->handle),name,0)) {
                        show_error("unlink",name);
	                opers.write_errors++;
	                return -1;
	        }
                opers.entries_removed++;
        }
    return 0;
}

const Entry *directory_lookup(const Directory *d, const char *name) {
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

static int should_exclude(const Directory *from, const Entry *entry) {
    Exclude *e=exclude_list;

    while(e) {
	if (regexec(&e->regex,entry->name,0,NULL,0)==0) {
	    /* Matched */
	    return 1;
	}
	e=e->next;
    }
    return 0;
}

/* Remove missing files and directories which exist in to but in from */
int remove_old_entries(Directory *from,
		       Directory *to) {
    int to_i=0;

    for(to_i=0; to && to_i < to->entries; to_i++) {
	
	if ( directory_lookup(from,to->array[to_i].name)==NULL) {
	    /* Entry no longer exists in from and should be removed if --delete is in effect */
	    remove_entry(to->array[to_i].name,to,&to->array[to_i].stat);
	} 

	if (opers.write_errors) return -1;
    }
    return 0;
}

/*
 * Returns 1 if the from entry considered newer, changed or just different
 * than to entry
 */
int entry_changed(const Entry *from, const Entry *to) {
    if (from->state != ENTRY_GOOD) {
	/* If there was problems checking the file attributes, we probably
	 * cannot access it anyway. So we return 'not changed' (and skip it).
	 */
	return 0;
    }

    if (to->state != ENTRY_GOOD) {
	/* Even when we cannot get the matching target file 
	 * attributes, we might be able to unlink it. So we try to copy it.
	 */
	return 1;
    }

    /* At this point we know, that we have the stat information of both
     * source and target files */

    if (update_all) {
	/* If we have update_all we update everything we can */
	return 1;
    }
	
    if (S_ISDIR(from->stat.st_mode)) {
	/* Directories will be always handled */
	return 1;
    }

    if (preserve_owner && from->stat.st_uid!=to->stat.st_uid) {
	/* Owner changed and preserved */
	return 1;
    }
    
    if (preserve_group && from->stat.st_gid!=to->stat.st_gid) {
	/* Group changed */
	return 1;
    }

    if (preserve_permissions && from->stat.st_mode!=to->stat.st_mode) {
	/* Permissions changed */
	return 1;
    }

    /* If size is different we need to copy the file */
    if (from->stat.st_size!=to->stat.st_size) {
        return 1;
    }

    /* If from is newer by mtime it has changed. Fixme: handle nanosecond timestamps. We already copy them. */
    if (from->stat.st_mtime>to->stat.st_mtime) {
	return 1;
    }

    /* Regular file and we have found no reason to copy it.*/
    if (S_ISREG(from->stat.st_mode) && S_ISREG(to->stat.st_mode)) {
        return 0;
    }

    /* With symlinks we cannot just compare modification times:
     * they will be different, because there is no way to change
     * mtime of a symlink! */
    if (S_ISLNK(from->stat.st_mode) && 
	S_ISLNK(to->stat.st_mode) &&
	strcmp(from->link,to->link)==0) {
	/* Symlinks do not match */
	return 0;
    }
    
    /* fprintf(stderr,"Just different: %s %s\n",from->name,to->name); */

    /* entries we're different */
    return 1;
}

int check_hard_link(const Entry *fentry, const char *target) {
    int hval=(fentry->stat.st_ino+fentry->stat.st_dev)%hash_size;
    Link *l;
    struct stat target_stat;

    /* Lookup in the hash table */
    for(l=link_htable[hval];
	l && 
	    (l->source_dev!=fentry->stat.st_dev ||
	     l->source_ino!=fentry->stat.st_ino);
	l=l->next);
    if (l) {
	/* Found the entry from hash table */
	if (!dryrun) {
	    if (link(l->target_name,target)<0) {
		show_error("link",target);
		return 1;
	    }
	    if (lstat(target,&target_stat)<0 ||
		target_stat.st_ino!=l->target_ino ||
		target_stat.st_dev!=l->target_dev) {
		show_warning("hard link source changed",l->target_name);
	    }
	}
	if (verbose) {
	    printf("HL: %s -> %s\n",target,l->target_name);
	}
	opers.hard_links_created++;
	return 0;
    }
    /* Not found from table */
    return 1;
	
}

void save_link_info(const Entry *fentry, const char *path) {
    int hval=(fentry->stat.st_ino+fentry->stat.st_dev)%hash_size;
    Link *link=NULL;
    struct stat target;
    if (!dryrun && lstat(path,&target)<0) {
	/* Should not happen (tm) */
	    show_error("save link info lstat failed (?)",path);
	return;
    }
    link=malloc(sizeof(Link));
    if (!link) {
	perror("malloc");
	return;
    }
    link->source_ino=fentry->stat.st_ino;
    link->source_dev=fentry->stat.st_dev;
    if (dryrun) {
	link->target_ino=0;
	link->target_dev=0;
    } else {
	link->target_ino=target.st_ino;
	link->target_dev=target.st_dev;
    }
    link->target_name=strdup(path);
    if (!link->target_name) {
	perror("strdup");
	free(link);
	return;
    }
    link->next=link_htable[hval];
    link_htable[hval]=link;
}
    
int dsync(Directory *from_parent, const char *source, 
        Directory *to_parent, const char *target, off_t offset) {
    struct stat cdir;
    int fromfd=-1;
    int tofd=-1;
    Directory *from=NULL;
    Directory *to=NULL;
    int i;
    int ret=-1;
    int tolen=strlen(target);
    char todir[MAXLEN];
    struct JobList {
        Job *job;
        struct JobList *next;
    } *joblist=NULL;

    strncpy(todir,target,sizeof(todir));
    //printf("DS %ld: %s\n",offset,todir);

    from=pre_scan_directory(source,from_parent);
    if (from==NULL) {
	show_error("readdir",source);
	opers.read_errors++;
	goto fail;
    }
    if ( fstat(dirfd(from->handle),&cdir) < 0 ){
        perror("fstat");
        exit(1);
    }
  
    if (from->entries>0) show_progress("Scanning a directory.");

    to=pre_scan_directory(todir,to_parent);

    if ( delete_only && to==NULL ) {
	if (verbose) {
	    printf("NE: %s\n",todir);
	}
	return 0;
    }
    if ( !dryrun && to==NULL) {
	show_error("readdir",todir);
	opers.write_errors++;
	goto fail;
    }
    
    if (delete) remove_old_entries(from, to);

    /* Loop through the source directory entries */
    for(i=0;i<from->entries &&
	    opers.write_errors==0
	    ;i++) {
	const Entry *fentry=&from->array[i];
	const Entry *tentry=NULL;

	/* Progress output? */
	show_progress(todir);
	    
	/* Check if this entry should be excluded */
	if (should_exclude(from,fentry)) {
                continue;
        }

	snprintf(todir+tolen,MAXLEN-tolen,"/%s",fentry->name);
	
	/* Lookup the existing file */
	if (to) tentry=directory_lookup(to,todir+tolen+1);		

	/* Check if the already existing target file is OK, 
	 * or should we remove it */
	if (tentry) {
	    if (entry_changed(fentry,tentry)) {
		if (!S_ISDIR(fentry->stat.st_mode) || 
		    !S_ISDIR(tentry->stat.st_mode)) {
		    if (delete || !S_ISDIR(tentry->stat.st_mode)) {
			/* Entry exists, but it is OK to remove it */
			todir[tolen]='\0';
			remove_entry(tentry->name,to,&tentry->stat);
			todir[tolen]='/';
		    } else {
			show_warning("Directory is in the way. Consider --delete",todir);
			opers.write_errors++;
			continue;
		    }
		}
	    } else {
		if (verbose>=2) {
		    printf("OK: %s\n",todir);
		}
		continue;
	    }
	}

	if (!delete_only) {
	    /* Check for hard links */
	    if (fentry->stat.st_nlink>1 &&
		!S_ISDIR(fentry->stat.st_mode)) {
		static int link_count_warned=0;
		/* Found a hard link */
		if (preserve_hard_links) {
		    if (check_hard_link(fentry,todir)==0) {
			/* Hard link was created */
			continue;
		    }
		} else if (!link_count_warned) {
		    show_warning("Hard links found. Consider --hard-links option",todir);
		    link_count_warned=1;
		}
	    }

	    if (create_target(from,fentry->name,to,fentry->name,fentry)<0) {
		/* Failed to create new entry */
		continue;
	    }

	    /* Save paths to entries having link count > 1 
	     * for making hard links */
	    if (preserve_hard_links &&
		fentry->stat.st_nlink>1 &&
		!S_ISDIR(fentry->stat.st_mode)) {
		save_link_info(fentry,todir);		
	    }
	}


	/* Check if we need to recurse into subdirectory */
	if (S_ISDIR(fentry->stat.st_mode) && 
	    one_file_system && 
	    fentry->stat.st_dev!=cdir.st_dev) {
	    /* On different file system and one_file_system was given */
	    scans.dirs_skipped++;
	    if (verbose) printf("FS: %s\n",todir);
	    
	} else if (fentry->stat.st_ino == target_stat.st_ino && 
		   fentry->stat.st_dev == target_stat.st_dev ) {
	    /* Attempt to recurse into destination directory */ 
	    scans.dirs_skipped++;
	    if (verbose) printf("TD: %s\n",todir);

	} else if ( tentry && 
		    tentry->stat.st_ino == source_stat.st_ino &&
		    tentry->stat.st_dev == source_stat.st_dev ) {
	    /* Attempt to recurse into source directory */
	    scans.dirs_skipped++;
	    if (verbose) printf("SD: %s\n",todir);
	
	} else if (S_ISDIR(fentry->stat.st_mode)) {
	    /* All checks turned out green: we recurse into a subdirectory */

            struct JobList *job=calloc(sizeof(*job),1);
            if (!job) {
                perror("calloc");
                exit(1);
            }
            job->job=submit_job(from,fentry->name,to,fentry->name,offset+1,dsync);
            job->next=joblist;
            joblist=job;

            #if 0
	    dsync(from,fentry->name,to,todir);
            if ( fchdir(dirfd(from->handle)) ) {
                perror("fchdir");
                exit(1);
            }
	    #endif 
	}

	/* Check if we need to update the inode bits */
	if (!dryrun && !delete_only) {

                /* UID and GID */
                uid_t uid=-1;
                gid_t gid=-1;
                if (preserve_owner && (tentry==NULL || tentry->stat.st_uid != fentry->stat.st_uid) ) {
                        uid=fentry->stat.st_uid;
                }
                if (preserve_group && (tentry==NULL || tentry->stat.st_gid != fentry->stat.st_gid) ) {
                        gid=fentry->stat.st_gid;
                }
                if (uid!=-1 || gid!=-1) {
		        if ( fchownat(dirfd(to->handle),fentry->name, uid, gid,AT_SYMLINK_NOFOLLOW)<0 ) {
		                show_error("lchown",todir);
		                opers.write_errors++;
                        } else opers.chown++;
		}

                // Permissions 
	        if (preserve_permissions && 
		        !S_ISLNK(fentry->stat.st_mode) &&
                        (!tentry || fentry->stat.st_mode!=tentry->stat.st_mode) ) {
		        if (fchmodat(dirfd(to->handle),fentry->name,fentry->stat.st_mode,AT_SYMLINK_NOFOLLOW)<0) {
		                show_error("fchmodat",todir);
		                opers.write_errors++;
                        } else opers.chmod++;
	        }

	    if ( (preserve_time || atime_preserve) && !S_ISLNK(fentry->stat.st_mode)) {
		struct timespec tmp[2] = {
                        { .tv_sec=0, .tv_nsec=UTIME_NOW },
                        { .tv_sec=0, .tv_nsec=UTIME_NOW }
                };
                if (tentry) {
                        tmp[0]=tentry->stat.st_atim;
                        tmp[1]=tentry->stat.st_mtim;
                }
                if (atime_preserve) tmp[0]=fentry->stat.st_atim;
                if (preserve_time) tmp[1]=fentry->stat.st_mtim;
                if (atime_preserve||preserve_time) {
                        if (tentry && 
                                tentry->stat.st_atim.tv_sec == tmp[0].tv_sec &&
                                tentry->stat.st_atim.tv_nsec == tmp[0].tv_nsec &&
                                tentry->stat.st_mtim.tv_sec == tmp[1].tv_sec &&
                                tentry->stat.st_mtim.tv_nsec == tmp[1].tv_nsec 
                        ) {
                                /* skip, times were right */
                        } else if (utimensat(dirfd(to->handle),fentry->name,tmp,AT_SYMLINK_NOFOLLOW)<0) {
                                show_error("utimensat",todir);
                                opers.write_errors++;
                        } else opers.times++;
                }

	    }
	}
    }

    ret=0;

fail:
    int failed_jobs=0;
    while(joblist) {
        if (wait_for_job(joblist->job)) failed_jobs++;
        struct JobList *tmp=joblist;
        joblist=joblist->next;
        free(tmp);
    }
    if (failed_jobs>0) fprintf(stderr,"SD %ld: %d failed jobs\n",offset,failed_jobs);
    if (fromfd>=0) close(fromfd);
    if (tofd>=0) close(tofd);
    if (from) d_freedir(from);
    if (to) d_freedir(to);
    todir[tolen]=0;
    return ret;
}

/* Hello world job to test job submission. */
int hello_job(Directory *from, const char *source, Directory *to, const char *target, off_t offset) {
        printf("Hello world going to sleep %s %ld\n",source, offset);
        sleep(1);
        printf("Hello world waking up %s %ld\n",source, offset);
        return 123;
}


int main(int argc, char *argv[]) {

    memset(&scans,0,sizeof(scans));
    memset(&opers,0,sizeof(opers));

    /* Check the options */
    parse_options(argc, argv);
 
    if (safe_mode && !quiet) {
        printf("Running in in slower safe mode: removing access to users before updating targets.\n");
    }
    myuid=getuid();
    if (argc-optind!=2) {
	fprintf(stderr,"Need to have source and destination dirs\n");
	show_help();
	exit(1);
    }

    if (preserve_hard_links) {
	/* Init the hash table */
	if ( (link_htable=malloc(sizeof(Link *)*hash_size))==NULL ) {
	    perror("malloc");
	    exit(2);
	}
	memset(link_htable,0,sizeof(Link *)*hash_size);
    }
    
    /* Start the pre-scanning thread if needed */
    if (threads) start_job_threads(threads);
    
    if (realpath(argv[optind+1],s_topath)==NULL) {
        fprintf(stderr,"realpath() failed for %s\n",argv[optind+1]);
        exit(1);
    }
    if (stat(s_topath,&target_stat)<0 || 
	!S_ISDIR(target_stat.st_mode)) {
	fprintf(stderr,"target '%s' is not a directory.\n",s_topath);
	exit(1);
    }
    if (chdir(argv[optind])<0) {
	fprintf(stderr,"chdir('%s'): %s\n",argv[optind],strerror(errno));
	exit(1);
    }
    if (stat(".",&source_stat)<0 ||
	!S_ISDIR(source_stat.st_mode)) {
	fprintf(stderr,"stat('%s'): %s\n",argv[optind],strerror(errno));
	exit(1);
    }
    if (getcwd(s_frompath,sizeof(s_frompath))==NULL)  {
        fprintf(stderr,"getcwd(source_dir) failed: %s",strerror(errno));
        exit(1);
    }

    target_dir=strdup(s_topath);
    if (!target_dir) {
	perror("strdup");
    }
    target_dir_len=strlen(target_dir);

     // Subnt testing
    //Job *job=submit_job(NULL,"/HELLO/!",NULL,NULL,666,hello_job);
 
    dsync(NULL, s_frompath, NULL, s_topath,0);

    // result testing
    //printf("job result %d\n",wait_for_job(job));

    if (opers.no_space && !delete_only) {
	show_warning("Out of space. Consider --delete.",NULL);
    }
    if (opers.write_errors) {
	fprintf(stderr,"dsync was canceled because of write errors.\n");
    }

    if (!quiet) {
	if (dryrun) printf("dryrun:\n");
	print_scans(&scans);
	print_opers(&opers);
    }
    if (dryrun) {
	Opers dummy;
	memset(&dummy,0,sizeof(dummy));
	if (memcmp(&dummy,&opers,sizeof(dummy))==0) {
	    /* No operations */
	    return 0;
	} else {
	    return 1;
	}
    } else {
	if (opers.read_errors==0 && opers.write_errors==0) {
	    /* No failures */
	    return 0;
	} else {
	    return 1;
	}
    }
    exit(0);
}
