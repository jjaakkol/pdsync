/*
 * dsync.c - Parallel Directory Sync Tool
 * Copyright (C) 2004 - 2025 Jani Jaakkola <jani.jaakkola@helsinki.fi>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "dsync.h"
#include <sys/mman.h>
#include <sys/xattr.h>
#include <sys/ioctl.h>
#include <linux/fs.h>

// User selected options
static char* const *static_argv;
static int dryrun=0;
static int delete=0;
static int delete_only=0;
static int one_file_system=0;
static int atime_preserve=0;
static int itemize=0;
static int quiet=0;
static int stats=0;
static int preserve_permissions=0;
static int preserve_owner=0;
static int preserve_group=0;
static int preserve_time=0;
static int preserve_devices=0;
static int preserve_links=0;
static int preserve_sparse=0;
static int preserve_hard_links=0;
int recursive=0;
static int safe_mode=0;
static int update_all=0;
static int show_warnings=1;
static int check=0;
static int reflink=0;
int privacy=0;
int progress=0;
int threads=4;
int debug=0;
const char *sync_tag=NULL;
const char *sync_tag_name="user.pdsync";
size_t copy_job_size = 1 * 1024 * 1024; // Default copy_job_size 1MB

// FIXME: get rid of globals
uid_t myuid=0;
FILE *tty_stream=NULL; /* For --progress */

typedef struct ExcludeStruct {
    regex_t regex;
    struct ExcludeStruct *next;
} Exclude;

Exclude *exclude_list=NULL;
Exclude **last_excluded=&exclude_list;

// TODO static source and target paths should probly be removed
static char s_topath[MAXLEN];
static char s_frompath[MAXLEN];
Entry source_root;
static struct stat source_stat;
struct {
        struct stat stat;
} target_root;

typedef struct {
        atomic_llong dirs_created;
        atomic_llong files_copied;
        atomic_llong files_reflinked;
        atomic_llong files_updated;
        int entries_removed;
        int dirs_removed;
        atomic_llong bytes_copied;
        atomic_llong sparse_bytes;
        atomic_llong symlinks_created;
        atomic_llong fifos_created;
        int hard_links_created;
        atomic_llong chown;
        atomic_llong chmod;
        atomic_llong times;
        atomic_llong items;             // Number of of operations listed with --itemize
        atomic_llong sync_tags;         // sync_tags created

        // Errors and warnings
        atomic_llong sockets_warned;
        atomic_llong devs_warned;
        atomic_llong chown_warned;
        atomic_llong read_errors;
        atomic_llong write_errors;
        atomic_llong error_espace;
} Opers; 
Opers opers;
Scans scans;

typedef struct LinkStruct {
    dev_t source_dev;
    ino_t source_ino;
    dev_t target_dev;
    ino_t target_ino;
    char *target_path;       // Path to the link source
    struct LinkStruct *next;
} Link;

static Link **link_htable=NULL;
static int hash_size=1009;
static pthread_mutex_t link_htable_mutex=PTHREAD_MUTEX_INITIALIZER;

// -- options
enum {
        ATIME_PRESERVE=255,
        PRIVACY=256,
        DELETE_ONLY=257,
        THREADS=258,
        SYNC_TAG=259,
        SYNC_TAG_NAME=260,
        DEBUG=261,
        CHECK=262,
        STATS=263,
        REFLINK=264,
        COPY_JOB_SIZE=265
};

static struct option options[]= {
                { "copy-job-size",   1, NULL, COPY_JOB_SIZE },
        { "dry-run",         0, NULL, 'n' },
        { "itemize",         0, NULL, 'i' },
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
        { "sync-tag",        1, NULL, SYNC_TAG },
        { "sync-tag-name",   1, NULL, SYNC_TAG_NAME },
        { "debug",           0, NULL, DEBUG },
        { "check",           0, NULL, CHECK },
        { "stats",           0, NULL, STATS },
        { "reflink",         0, NULL, REFLINK },
        { NULL, 0, NULL, 0 }
};

JobResult sync_directory(Directory *from_parent, Entry *parent_fentry, Directory *to_parent, const char *target, off_t offset);
JobResult sync_metadata(Directory *not_used, Entry *fentry, Directory *to, const char *target, off_t offset);

#ifndef VERSION
        #define VERSION "1.9-build"
#endif
static void show_version() {
    printf("pdsync %s (C) 09.2000 - 05.2025 Jani Jaakkola (jani.jaakkola@helsinki.fi)\n", VERSION);
}

static void show_help() {
    int i;
    int len=0;
    show_version();
    printf("Usage: pdsync [options] <fromdir> <todir>\n");
    printf("pdsync is a tool for synchronization of two local directories.\n");
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
        printf("\n    --copy-job-size <MB>   Set the copy job size in megabytes (default: 1)\n");
        putchar('\n');
}

void show_error(const char *why, const char *file) {
        fprintf(stderr,"Error: %s %s: %s\n",why,
	        (privacy) ? "[PRIVATE]":file,
	        (errno==0) ? "errno==0" : strerror(errno));
}

void read_error(const char *why, const Directory *d, const char *file) {
        atomic_fetch_add(&opers.read_errors, 1);
        show_error("Read error:", file_path(d, file));
}

void write_error(const char *why, const Directory *d, const char *file) {
        if (errno==ENOSPC) {
	        atomic_fetch_add(&opers.error_espace, 1);
        }
        atomic_fetch_add(&opers.write_errors, 1);
        show_error(why, file_path(d, file));
        fprintf(stderr,"Write error, exiting immediately\n");
        exit(2);
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

// Write a item a shell executable command about what was done
static void item(const char *i, const Directory *d, const char *name ) {
        FILE *stream=stdout;
        atomic_fetch_add(&opers.items,1);
        if (!itemize) return;
        fprintf(stream,"%s: %s%s\n",i,dir_path(d),name);
}

// it itemize>1 we write an entry of skipped items
static void item2(const char *i, const Directory *d, const char *name ) {
        FILE *stream=stdout;
        if (itemize<2) return;
        fprintf(stream,"# %s: %s%s\n",i,dir_path(d),name);
}


const char *format_bytes(long long bytes, char output[static 32]) {
        if (bytes < 1024) {
                snprintf(output, 32, "%5lldB", bytes);
        } else if (bytes < 1024 << 10 ) {
                snprintf(output, 32, "%.1fKiB", bytes / 1024.0);
        } else if (bytes < 1024 << 20) {
                snprintf(output, 32, "%.1fMiB", bytes / (1024.0 * 1024));
        } else if (bytes < 1024LL << 30) {
                snprintf(output, 32, "%.1fGiB", bytes / (1024.0 * 1024 * 1024));
        } else {
                snprintf(output, 32, "%.1fTiB", bytes / (1024.0 * 1024 * 1024 * 1024));
        }
        return output;
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
	case 'i': itemize++; break;
	case 'P': 
	        tty_stream=(tty_stream>0) ? tty_stream :fopen("/dev/tty","w");
	        if (!tty_stream) {
		        fprintf(stderr,"Warning: could not open /dev/tty. Using stderr for progress reports.\n");
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
	case 'D': preserve_devices=1;
                fprintf(stderr,"Warning: preserving devices is not implemented yet.\n");
                exit(1);
                break;
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
                        if (!optarg[0] || *endptr || threads<1 || threads > 256 ) {
                                fprintf(stderr,"Invalid value given to --threads: '%s'\n",optarg);
                                exit(1);
                        }
                        break;
                }
        case SYNC_TAG_NAME: sync_tag_name=optarg; break;
        case SYNC_TAG: sync_tag=optarg; break;
        case DEBUG: debug++; fprintf(stderr,"Debug: %d\n",debug); break;
	case CHECK: check=1; break;
        case REFLINK: reflink=1; break;
        case STATS: stats++; break;
        case COPY_JOB_SIZE:
                        char *endptr = NULL;
                        long mb = 0;
                        if (optarg && (mb=strtol(optarg, &endptr, 10))>0 && endptr && *endptr == '\0' && mb<128) {
                                copy_job_size = (size_t)mb * 1024 * 1024;
                        } else {
                                fprintf(stderr, "Invalid value for --copy-job-size: %s\n", (optarg) ? optarg : "''");
                                exit(1);
                        }
                        break;
	case 'a':
	    recursive=1;
	    preserve_permissions=1;
	    if (geteuid()==0) preserve_owner=1;  // Only preserve owner if running as root
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

// Fixme: print to a given stream
static void print_scans(const Scans *scans) {
    if (scans->slow_io_secs) {
        printf("%8d seconds of slow IO\n", scans->slow_io_secs);
    }
    if (scans->dirs_read) {
	printf("%8d directories read\n",scans->dirs_read);
    }
    if (scans->entries_checked) {
	printf("%8d files checked\n",scans->entries_checked);
    }
    if (scans->hard_links_saved) {
        printf("%8d hard links found\n", scans->hard_links_saved);
    }
    if (scans->dirs_skipped) {
	printf("%8d directories skipped\n",scans->dirs_skipped);
    }
    if (scans->files_skipped) {
        printf("%8d files skipped\n",scans->files_skipped);
    }
    if (scans->jobs_run) {
        printf("%8lld total number of jobs run\n", scans->jobs_run);
    }
    if (scans->jobs_waiting) {
        printf("%8d jobs waiting\n", scans->jobs_waiting);
    }
    if (scans->dirs_active>=0) {
        printf("%8d directories in memory now\n",scans->dirs_active);
    }
    if (scans->dirs_active_max) {
	printf("%8d maximum number of directories in memory\n",
	       scans->dirs_active_max);
    }
    if (scans->open_dir_count) {
        printf("%8d directories open now\n",scans->open_dir_count);
    }
    if (scans->dirs_freed) {
        printf("%8d directories freed\n",scans->dirs_freed);
    }
    if (scans->read_directory_jobs>0) {
	printf("%8d read directory jobs left\n",scans->read_directory_jobs);
    }
}

static void print_opers(FILE *stream, const Opers *stats) {
        struct timespec now;

        clock_gettime(CLOCK_BOOTTIME, &now);
        long ns = (now.tv_sec*1000000000L + now.tv_nsec) - 
                scans.start_clock_boottime.tv_sec*1000000000L + scans.start_clock_boottime.tv_nsec;
        long s = ns / 1000000000L;
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &now);

        // I've spent too long this...
        fprintf(stream,"# ");
        for(int i=0;static_argv[i];i++) fprintf(stream," %s",static_argv[i]);
        fprintf(stream,"\n");
        fprintf(stream, "Walltime %02lld:%02lld:%02lld.%03lld,",
                s / 3600LL, (s / 60LL) % 60, s % 60LL, ns/1000000LL % 1000 );
        fprintf(stream, " CPUtime %02lld:%02lld:%02lld.%03lld (%.1f%%)\n",
                now.tv_sec / 3600LL, (now.tv_sec / 60LL) % 60, now.tv_sec % 60LL, now.tv_nsec/1000000LL % 1000,
                100.0 * (now.tv_sec*1000000000 + now.tv_nsec) / ns);
        if (stats->dirs_created) {
                fprintf(stream, "%8lld directories created\n", stats->dirs_created);
        }
    if (stats->dirs_removed) {
        fprintf(stream, "%8d directories removed\n", stats->dirs_removed);
    }
    if (stats->entries_removed) {
        fprintf(stream, "%8d entries removed\n", stats->entries_removed);
    }
    if (stats->files_copied) {
        fprintf(stream, "%8lld files copied, %.1ff/s\n", stats->files_copied,
                stats->files_copied*1000000000.0/ns);
    }
    if (stats->files_reflinked) {
        fprintf(stream, "%8lld files reflinked", stats->files_reflinked);
    }
    char buf[32];
    fprintf(stream, "%8s bytes copied, ", format_bytes(stats->bytes_copied, buf));
    fprintf(stream, "%s/s\n", format_bytes(stats->bytes_copied*1000000000.0/ns,buf));    
    fprintf(stream, "%8s bytes checked, ", format_bytes(scans.bytes_checked, buf));
    fprintf(stream, "%s/s\n", format_bytes(scans.bytes_checked*1000000000.0/ns,buf));
    if (scans.bytes_skipped) {
        fprintf(stream, "%8s bytes skipped\n", format_bytes(scans.bytes_skipped, buf));
    }
    if (stats->sparse_bytes) {
        fprintf(stream, "%8s data in sparse blocks\n", format_bytes(stats->sparse_bytes, buf));
    }
    if (stats->symlinks_created) {
        fprintf(stream, "%8lld symlinks created\n", stats->symlinks_created);
    }
    if (stats->hard_links_created) {
        fprintf(stream, "%8d hard links created\n", stats->hard_links_created);
    }
    if (stats->fifos_created) {
        fprintf(stream, "%8lld fifos created\n", stats->fifos_created);
    }
    if (stats->chown) {
        fprintf(stream,"%8lld file owner/group changed\n", stats->chown);
    }
    if (stats->chmod) {
        fprintf(stream,"%8lld file chmod bits changed\n", stats->chmod);
    }
    if (stats->times) {
        fprintf(stream,"%8lld file atime/mtime changed\n", stats->times);
    }
    if (stats->sync_tags) {
        fprintf(stream,"%8lld sync tags set\n", stats->sync_tags);
    }
    if (stats->sockets_warned) {
        fprintf(stream, "%8lld sockets skipped\n", stats->sockets_warned);
    }
    if (stats->devs_warned) {
        fprintf(stream, "%8lld device nodes skipped\n", stats->devs_warned);
    }
    if (stats->chown_warned) {
        fprintf(stream, "%8lld chown failed\n", stats->chown_warned);
    }
    if (stats->read_errors) {
        fprintf(stream, "%8lld errors on read\n", stats->read_errors);
    }
    if (stats->write_errors) {
        fprintf(stream, "%8lld errors on write\n", stats->write_errors);
    }
}

// Print the progress to ttysream, obeying privacy options. Called from a thread once a second
void print_progress() {
        static int last_synced=0;
        static long long last_bytes;
        static long long last_ns=0;
        static long long last_jobs_run=0;
        static int slow_secs=0;
        char status[64]="";

        char B[32];
        char BpS[32];

        if (!progress) return;
 
        struct timespec now;
        clock_gettime(CLOCK_BOOTTIME, &now);
        long long now_ns = now.tv_nsec + now.tv_sec * 1000000000L;

        // I've spent too long this...
        if (progress>=2) {
                fprintf(tty_stream,"\033[2J\033[H### Pdsync syncing '%s' -> '%s'\n", s_frompath, s_topath);
        }
        long s = now.tv_sec - scans.start_clock_boottime.tv_sec;

        // Check for stalled progress
        if (last_jobs_run==scans.jobs_run) {
                snprintf(status, sizeof(status)-1, "stalled %ld secs", s-slow_secs);
        } else slow_secs=s;

        int files_synced=atomic_load(&scans.files_synced);
        // FIXME: get rid of descendants
        int files_total=(source_root.dir) ? atomic_load(&source_root.dir->descendants) + source_root.dir->entries : 0;
        const char *less_or_equal = (scans.read_directory_jobs>0) ? "<" : "=";
        float percent=100;
        if (files_total>0) percent=(100.0*files_synced)/files_total;
        fprintf(tty_stream, "\033[K PG %02lld:%02lld:%02lld | ", s / 3600LL, (s / 60LL) % 60, s % 60LL );
        fprintf(tty_stream,"%d/%d files %s%2.1f%% |%7.1ff/s |%9s |%9s/s | %7.1f jobs/s | %d/%d queued|%3d idle | %s\n",
                files_synced,
                files_total,
                less_or_equal, percent,
                1000000000.0 * (files_synced-last_synced) / (now_ns-last_ns),
                format_bytes(opers.bytes_copied, B),
                format_bytes( 1000000000.0L *(opers.bytes_copied-last_bytes) / (now_ns-last_ns),BpS),
                1000000000.0 *(scans.jobs_run-last_jobs_run) / (now_ns-last_ns),
                scans.queued, scans.maxjobs,
                scans.idle_threads,
                status
        );
        if (progress==1) fprintf(tty_stream,"\033[1A");
        if (progress>=2) print_opers(tty_stream,&opers);
        if (progress>=3) print_scans(&scans);
        fflush(tty_stream);
        last_synced=files_synced;
        last_bytes=opers.bytes_copied;
        last_ns=now_ns;
        last_jobs_run=scans.jobs_run;
}

// Unlink one target entry, which is not a directory
int unlink_file(Directory *parent, const char *name) {
        assert(delete);
        int ret=0;

        int dfd=dir_open(parent);
        if (!dryrun && unlinkat(dfd, name, 0)) {
                write_error("unlink", parent, name);
                ret=-1;
        } else  {
                item("rm -f", parent,name);
                opers.entries_removed++;
        }
        dir_close(parent);
        return ret;
}

int unlink_entry(Directory *parent, Entry *e) {
        assert(e && e->name);
        return unlink_file(parent, e->name);
}

JobResult remove_directory(Directory *ignored, Entry *tentry, Directory *del, const char *not_used, off_t depth) {
        assert(tentry->dir && del==tentry->dir);
        set_thread_status(file_path(tentry->dir, tentry->name), "rmdir");
        int ret=0;
        int dfd=-1;
        if (!dryrun) {
                if ( (dfd=dir_open(del->parent))<0 || unlinkat(dfd, tentry->name, AT_REMOVEDIR )<0) {
	                write_error("rmdir", tentry->dir, tentry->name);
                        goto fail; 
                }
        }
        item("rmdir", tentry->dir, tentry->name);
        opers.dirs_removed++;
        fail:
        if (dfd>=0) dir_close(del->parent);
        return ret;
}

JobResult remove_hierarchy(Directory *ignored, Entry *tentry, Directory *to, const char *ignored_too, off_t depth) {
        struct stat thisdir;
        Directory *del=NULL;
        int i;
 
        // We only read_directory. fstat of the removed inodes is not
        del=read_directory(to, tentry);
        if (!del) {
                write_error("read_directory", to, tentry->name);
                goto fail;
        }
        int dfd=dir_open(del);
        if (dfd<0) goto fail;
        fstat(dfd,&thisdir);
        if (thisdir.st_dev==source_stat.st_dev &&
        	thisdir.st_ino==source_stat.st_ino) {
        	/* This can happen when doing something like 
	        * dsync /tmp/foo/bar /tmp/foo */
        	show_warning("Skipping removal of source directory", file_path(to, tentry->name));
	        goto fail;
        }
        if (thisdir.st_dev==target_root.stat.st_dev &&
	        thisdir.st_ino==target_root.stat.st_ino) {
	        /* This should only happen on badly screwed up filesystems */
	        show_warning("Skipping removal of target directory (broken filesystem?).\n", file_path(to, tentry->name));
	        goto fail;
        }
  
        for(i=0;i<del->entries;i++) {
                set_thread_status(file_path(to, del->array[i].name), "unlinking");
                if (entry_isdir_i(del, i)) {
                        submit_job_first(NULL, &del->array[i], del, NULL, depth+1, remove_hierarchy);
                } else if ( unlink_entry(del, dir_entry(del, i)) ) {
                        goto fail; 
                }
	}
        submit_job(NULL, tentry, del, ".", DSYNC_DIR_WAIT, remove_directory); // del is freed by remove_directory()
        int ret=0;

 cleanup:
        if (dfd>=0) dir_close(del);
        if (del) d_freedir(del);

        return ret;

 fail:
        write_error("remove_hierarchy", to, tentry->name);
        ret=-1;
        goto cleanup;
}

// Copy a file, preserving sparseness by punching holes using fallocate and mmap() I/O
// Turns out this is really slow, at least with zfs.
int copy_regular_mmap(int fd_in, int fd_out, off_t filesize, off_t offset) {
        const size_t chunk_size = 16 * 1024 * 1024;
        const size_t min_hole = 128*1024; /* zfs default record size 128k */
        size_t written=0;
        size_t this_chunk = (filesize - offset > chunk_size) ? chunk_size : (size_t)(filesize - offset);
        char *dst=NULL;
        int ret=0;

        // mmap input
        char *src = mmap(NULL, this_chunk, PROT_READ, MAP_SHARED | MAP_NONBLOCK | MAP_POPULATE, fd_in, offset);
        if (src == MAP_FAILED) {
                fprintf(stderr,"mmap(%ld, %ld)\n",this_chunk, offset);
                goto fail; 
        }
        if (madvise(src, this_chunk, MADV_SEQUENTIAL)<0) perror("madvice src");
        if (madvise(src, this_chunk, MADV_WILLNEED)<0) perror("madvice src");

        // mmap output
        dst = mmap(NULL, this_chunk, PROT_WRITE|PROT_WRITE, MAP_SHARED|MAP_NONBLOCK|MAP_POPULATE, fd_out, offset);
        if (dst == MAP_FAILED) {
                perror("mmap() dst");
                goto fail;
        }
        if (madvise(dst, this_chunk, MADV_SEQUENTIAL)<0) perror("madvice dst");
        if (madvise(dst, this_chunk, MADV_WILLNEED)<0) perror("madvice dst");

        // Loop our chunk_size through in min_hole sized attempts at hole punching 
        while (written<this_chunk) {
                size_t i=0;
                size_t end_of_chunk = min_hole;
                // If it is EOC is past the EOF adjust
                if (written+end_of_chunk > this_chunk) end_of_chunk=this_chunk-written;

                // find the zero bytes and attempto to punch as large hole as we can
                while(preserve_sparse && i<end_of_chunk && src[i+written]==0) i++;
                if (i>=4096) {
                        if (fallocate(fd_out, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, offset+written, i) < 0) {
                                fprintf(stderr,"Disabling sparse files: fallocate(%ld): %s\n", i, strerror(errno));
                                preserve_sparse=0;
                                memset(dst+written, 0, i);
                        } else {
                                atomic_fetch_add(&opers.sparse_bytes, i);
                        }
                } else memset(dst+written, 0, i); // Don't bother punching less that 4096 byte holes

                // Then find bytes which are already equal, until end_of_chunk
                while(i<end_of_chunk && src[i+written]==dst[i+written]) i++;

                // Copy the rest of the bytes which aren't zero and aren't equal 
                memcpy(dst+written+i, src+written+i, end_of_chunk-i);
                atomic_fetch_add(&opers.bytes_copied, end_of_chunk-i);
                atomic_fetch_add(&scans.bytes_checked, end_of_chunk);
                written+=end_of_chunk;
        }

        out: 
        if (src) munmap(src, this_chunk);
        if (dst) munmap(dst, this_chunk);
        return ret;
        fail:
        ret=-1; 
        goto out;
}

// Copy file simply with regular read/write
int copy_regular_rw(int fd_in, int fd_out, off_t filesize, off_t offset) {
        const size_t bufsize=1*1024*1024;
        size_t this_chunk = (filesize - offset > copy_job_size) ? copy_job_size : (size_t)(filesize - offset);
        static _Thread_local char *buf=NULL;
        if (buf==NULL) buf=my_malloc(bufsize);

        if (lseek(fd_in, offset, SEEK_SET)!=offset) goto fail;
        if (lseek(fd_out, offset, SEEK_SET)!=offset) goto fail;

        // Loop through our chunk in bufsize rw 
        for(size_t written=0; written<this_chunk; ) {

                size_t r=read(fd_in, buf, bufsize);
                if (r<0) {
                        fprintf(stderr, "read(): %s\n", strerror(errno));
                        goto fail;
                }
                if (r==0) goto fail; // we got an EOF on our chunk

                if (update_all || check) {
                        static _Thread_local char *wbuf=NULL;
                        if (wbuf==NULL) wbuf=my_malloc(bufsize);
                        if (read(fd_out, wbuf, r)==r && memcmp(buf, wbuf, r)==0) {
                                // Identical bytes, we can skip the write
                                atomic_fetch_add(&scans.bytes_skipped, r);
                                written+=r;
                                atomic_fetch_add(&scans.bytes_checked, r);
                                continue;
                        }
                        if ( lseek(fd_out, offset+written, SEEK_SET) != offset+written ) goto fail;
                }


                size_t w=0;
                while (w<r) {
                        int ret=write(fd_out, buf+w, r-w);
                        if (ret<0) {
                                fprintf(stderr, "write(): %s\n", strerror(errno));
                                goto fail;
                        }
                        w+=ret;
                }
                written+=r;
                atomic_fetch_add(&opers.bytes_copied, w);
        }

        return 0; 
        fail: 
        return -1;
}

// Copy file with sendfile and option to seek a hole and punch hole to target
int copy_regular_sendfile(int fromfd, int tofd, off_t filesize, off_t offset) {
        off_t w=0;
        if ( lseek(fromfd,offset,SEEK_SET)<0 || lseek(tofd,offset,SEEK_SET)<0 ) {
                return -1;
        }

        off_t written=0;
        off_t to_copy=(offset + copy_job_size > filesize) ? filesize-offset : copy_job_size;

        while(written<to_copy) {
                off_t chunk=to_copy-written;

                // If preserve_sparse we punch holes
                if (preserve_sparse) {
                        off_t hole=lseek(fromfd, offset+written, SEEK_HOLE);
                        if (hole==offset+written) {
                                // Found a hole at this point . Punch a hole to target
                                off_t data=lseek(fromfd, hole, SEEK_DATA);
                                w=data-hole;
                                if (fallocate(tofd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, offset, w)<0) {
                                        fprintf(stderr,"Disabling sparse files: fallocate(%ld): %s\n", w, strerror(errno));
                                        preserve_sparse=0;
                                } else {
                                        atomic_fetch_add(&opers.sparse_bytes, w); // A hole was punched
                                        written+=w;
                                        lseek(tofd, offset+written, SEEK_SET);
                                }
                        }
                        // Move pointer back to the data and count the next copy chunk size
                        lseek(fromfd, offset+written, SEEK_SET);
                        chunk=hole-(offset+written);
                        if (written+chunk > to_copy) chunk=to_copy-written;
                }

                // Now copy the data
                if ( (w=sendfile(tofd, fromfd, NULL, chunk) )>0) {
                        atomic_fetch_add(&opers.bytes_copied, w);
                        written+=w;
                }
        }
        if (w<0) return -1;
        return 0;
}

// FIXME: split copy job submitting and actual copy function
int copy_regular(Directory *from, Entry *fentry, Directory *to, const char *target, off_t offset) {
        int fromfd=-1;
        int tofd=-1;
        int to_dfd=-1;
        int ret=0;
        char buf[32];
        int num_jobs=0;

        assert(from && to && fentry);
        const char *source=fentry->name;
        assert(source && target);

        if (fentry->state==ENTRY_FAILED) {
                return RET_FAILED;
        }

        if (dryrun) {
                item("CP",to,target);
                opers.bytes_copied+=entry_stat(fentry)->st_size;
                sync_metadata(from, fentry, to, target, 0);
                return 0;
        }

        int from_dfd = dir_open(from);
        fromfd=openat(from_dfd, source, O_RDONLY|O_NOFOLLOW);
        if (fromfd<0) {
                show_error_dir("open source", from, source);
                goto fail; 
        }
        num_jobs= (entry_stat(fentry)->st_size + copy_job_size - 1) / copy_job_size;

        to_dfd = dir_open(to);
        // mmap() IO needs RDWR access
        tofd = openat(to_dfd, target, O_RDWR | O_CREAT | O_NOFOLLOW,  0777);
        if(tofd<0) {
                write_error("open target", to, target);
                goto fail;
        }

        /* offset -1 means that this is the first job operating on this file */
        if (offset==-1) {

                // --reflink support happens here
                if (reflink) {
                        set_thread_status(file_path(to,target),"reflink clone");
                        int rc = ioctl(tofd, FICLONE, fromfd);
                        if (rc == 0) {
                                /* Cloned successfully */
                                item("cp --reflink", to, target);
                                atomic_fetch_add(&opers.files_reflinked, 1);
                                offset=0;
                                num_jobs=1;
                                goto end;
                        } else {
                                if (errno==EOPNOTSUPP || errno==ENOTTY || errno==EINVAL || errno==EXDEV) {
                                        write_error("Reflink not supported on filesystem", to, target);
                                } else {
                                        write_error("Reflink ioctl failed", to, target);
                                }
                                goto fail;
                        }
                }

                /* Check for sparse file */
                if ( entry_stat(fentry)->st_size/512 > entry_stat(fentry)->st_blocks ) {
	                static int sparse_warned=0;
	                if (!sparse_warned && !preserve_sparse) {
	                        show_warning("Sparse or compressed files detected. Consider --sparse option", source);
                                sparse_warned++;
                        }
	        }

                // If size doesn't match fruncate the target file
                Entry *tentry=directory_lookup(to, target);
                if (!tentry || entry_stat(tentry)->st_size!=entry_stat(fentry)->st_size) {
                        set_thread_status(file_path(to,target),"ftruncate");
                        if (ftruncate(tofd, entry_stat(fentry)->st_size) < 0) {
                                write_error("ftruncate", to, target);
                                goto fail;
                        }
                }

                /* Submit the actual copy jobs */
                if (entry_stat(fentry)->st_size<=16*1024) {
                        offset=0; // We have the file open and it is small. Copy it ourselves
                        if (entry_stat(fentry)->st_size==0) goto end; // Zero size file, skip copy
                } else {
                        for (int i=0; i<num_jobs; i++) {
                                submit_or_run_job(from, fentry, to, target, copy_job_size*i, copy_regular);
                        }
                        /* The metadata needs to be synced last. If there are multiple copy jobs, submit it last */
                        if (num_jobs>1) submit_job(from, fentry, to, target, DSYNC_FILE_WAIT, sync_metadata);
                        goto end;
                }
        }

        if (update_all || check) {
                if (preserve_sparse) {
                        snprintf(buf,sizeof(buf)-1,"update mmap %ld", offset/copy_job_size);
                        set_thread_status(file_path(to,target),buf);
                        if (copy_regular_mmap(fromfd, tofd, entry_stat(fentry)->st_size, offset)<0) {
                                write_error("copy_regular_mmap", to, target);
                        }
                } else {
                        snprintf(buf,sizeof(buf)-1,"update rw %ld", offset/copy_job_size);
                        set_thread_status(file_path(to,target),buf);
                        copy_regular_rw(fromfd, tofd, entry_stat(fentry)->st_size, offset);
                }
        } else {
                snprintf(buf,sizeof(buf)-1,"sendfile %ld", offset/copy_job_size);
                set_thread_status(file_path(to,target),buf);
                copy_regular_sendfile(fromfd, tofd, entry_stat(fentry)->st_size, offset);
        }

        if (offset/copy_job_size == num_jobs-1) {
                // This is the last job. Show copy done, even if some copy jobs might be still running
                item("CP",to,target);
                opers.files_copied++;
        }

        end:

        if (tofd>=0) close(tofd);
        if (fromfd>=0) close(fromfd);

        /* Optimization: if there was only one chunk of file to copy or 0 size file, we call sync_metadata immediately */
        if (offset==0 && num_jobs<=1) sync_metadata(from, fentry, to, target, 0);
        if (from_dfd>=0) dir_close(from);
        if (to_dfd>=0) dir_close(to);

        if (offset>=0) {
                snprintf(buf,sizeof(buf)-1,"copy %ld done", offset/copy_job_size);
                set_thread_status(file_path(to,target),buf);
        } else set_thread_status(file_path(to,target),"copy submitted");
        return ret;

        fail:
        item("# cp failed", to, target);
        fentry->state=ENTRY_FAILED;
        ret = RET_FAILED;
        goto end;
}

static int should_exclude(const Directory *from, const Entry *entry) {
    Exclude *e=exclude_list;

    while(e) {
	if (regexec(&e->regex,entry->name,0,NULL,0)==0) {
	    /* Matched */
            if (itemize>1) item("EX",from,entry->name);
	    return 1;
	}
	e=e->next;
    }
    return 0;
}

// Lookup a hard link entry from the hash table by source device and inode
// Returns the Link entry if found, NULL otherwise
// hard link mutex must be held
Link* lookup_hard_link(dev_t source_dev, ino_t source_ino) {
        int hval=(source_ino+source_dev)%hash_size;
        Link *l=link_htable[hval];

        while(l && (l->source_dev!=source_dev || l->source_ino!=source_ino) ) l=l->next;
        return l;
}

// Creating hard links cases which should be handled atomically:
// - new file:           used as target for hard linking later
// - existing 1st file:  used as target for hard linking later
// - more files:         should be replaced with a hard link
// Not actually a job, but could be made to be a job. 
JobResult create_hard_link(Directory *from, Entry *fentry, Directory *to, const char * target, Link *l) {
        assert(preserve_links && entry_stat(fentry)->st_nlink > 1 && S_ISREG(entry_stat(fentry)->st_mode) );
        assert(l);
        set_thread_status(file_path(to,target), "hard link");

        JobResult ret=RET_OK;
        int to_dfd=dir_open(to);
        struct stat ts;
        if (to_dfd<0) goto write_error;

        if (fstatat(to_dfd, target, &ts, AT_SYMLINK_NOFOLLOW)==0) {
                // The hard link target already exists
                if ( l->target_dev==ts.st_dev && l->target_ino==ts.st_ino ) {
                        // Correct link already exists
                        item2("# hard link ok", to, target);
                        goto out;
                }
                // The existing file should be removed if we are allowed to do so
                if (!S_ISREG(ts.st_mode) && !delete) {
                        // We aren't allowed to remove the entry
                        item2("# Something is in the way: can't create hardlink", to, target);
                        goto out;
                }
                if (unlinkat(to_dfd, target, 0)<0) goto write_error;
                item("rm -f", to, target);
        }

        // Now create the hard link
        if (!dryrun && linkat(AT_FDCWD, l->target_path, to_dfd, fentry->name, 0) <0 ) 
        {
                goto write_error;
        } else {
                if (itemize) printf("ln %s %s\n", l->target_path, file_path(to, target));
                opers.hard_links_created++;
        }

        out:
        if (to_dfd>=0) dir_close(to);
        return ret;

        write_error:
        write_error("Failed to create hard link", to, target);
        ret=RET_FAILED;
        goto out;

}

// Returns true if a create_hard_link() job was submitted to create the target
// so that caller chan skip rest of the processing
int check_hard_link(Directory *from, Entry *fentry, Directory *to, Entry *tentry) {
        if (!preserve_hard_links || entry_stat(fentry)->st_nlink < 2 || !S_ISREG(entry_stat(fentry)->st_mode) ) {
                return 0; // Nothing to check
        }

        pthread_mutex_lock(&link_htable_mutex);
        Link *l = lookup_hard_link(entry_stat(fentry)->st_dev, entry_stat(fentry)->st_ino);
        if (!l) {
                // We haven't seen this hard link yet. Save it in hash table.
                struct stat stat;
                if (!tentry || !S_ISREG(entry_stat(tentry)->st_mode)) {
                        // The hard link target file has not yet been created. Create it now.
                        copy_regular(from, fentry, to, fentry->name, -1);
                        if (file_stat(to, fentry->name, &stat) <0 ) {
                                write_error("hard link target creation", to, fentry->name);
                                return 1;
                        }
                } else {
                        stat=*entry_stat(tentry);
                }
                int hval=(entry_stat(fentry)->st_ino+entry_stat(fentry)->st_dev)%hash_size;
                Link *link=my_malloc(sizeof(Link));
                link->source_ino=entry_stat(fentry)->st_ino;
                link->source_dev=entry_stat(fentry)->st_dev;
                link->target_ino=stat.st_ino;
                link->target_dev=stat.st_dev;
                link->target_path=my_strdup(file_path(to, fentry->name));
                link->next=link_htable[hval];
                link_htable[hval]=link;
                atomic_fetch_add(&scans.hard_links_saved,1);
                pthread_mutex_unlock(&link_htable_mutex);
        } else {
                // We had already seen this link target. 
                pthread_mutex_unlock(&link_htable_mutex);
                create_hard_link(from, fentry, to, fentry->name, l);
        } 

        return 1;
}

/*
 * Returns 1 if the from entry considered newer, changed or just different
 * than to entry
 */
int entry_changed(Entry *from, Entry *to) {
        if (from->state==ENTRY_FAILED || to->state==ENTRY_FAILED) {
                return 0; // Nothing we can do here anymore
        }

        if (update_all) {
	        //If we have update_all we update everything we can */
	        return 1;
        }
	
        if (S_ISDIR(entry_stat(from)->st_mode)) {
	        /* Directories will be always handled */
	        return 1;
        }

        if (preserve_owner && entry_stat(from)->st_uid!=entry_stat(to)->st_uid) {
                /* Owner changed and preserved */
                return 1;
        }
    
        if (preserve_group && entry_stat(from)->st_gid!=entry_stat(to)->st_gid) {
                /* Group changed */
                return 1;
        }

        if (preserve_permissions && entry_stat(from)->st_mode!=entry_stat(to)->st_mode) {
                /* Permissions changed */
                return 1;
        }

        /* If size is different we need to at least update the file */
        if (entry_stat(from)->st_size!=entry_stat(to)->st_size) {
                return 1;
        }

        /* If we have preserve time any change in mtime is applied */
        if (preserve_time &&
                                (entry_stat(from)->st_mtime!=entry_stat(to)->st_mtime ||
                                entry_stat(from)->st_mtim.tv_nsec != entry_stat(to)->st_mtim.tv_nsec)) {
                return 1;
        }

        /* If we have --atime-preserve any change in atime is applied */
        if (atime_preserve &&
                                (entry_stat(from)->st_atime!=entry_stat(to)->st_atime ||
                                entry_stat(from)->st_atim.tv_nsec != entry_stat(to)->st_atim.tv_nsec) ) {
                return 1;
        }

        /* If from is newer by mtime it has changed. */
        if (entry_stat(from)->st_mtime>entry_stat(to)->st_mtime) {
                return 1;
        }
        if (entry_stat(from)->st_mtime == entry_stat(to)->st_mtime &&
                entry_stat(from)->st_mtim.tv_nsec > entry_stat(to)->st_mtim.tv_nsec) {
                return 1;
        }

        /* Regular file and we have found no reason to copy it.*/
        if (S_ISREG(entry_stat(from)->st_mode) && S_ISREG(entry_stat(to)->st_mode)) {
                return 0;
        }

        /* Don't recreate FIFOs if not needed .*/
        if (S_ISFIFO(entry_stat(from)->st_mode) && S_ISFIFO(entry_stat(to)->st_mode)) {
                return 0;
        }

        /* If symlink names match don't update it. */
        if (S_ISLNK(entry_stat(from)->st_mode) && 
                S_ISLNK(entry_stat(to)->st_mode) &&
                strcmp(from->link,to->link)==0) {
                return 0; // Symlinks match
        }

        // No reason to skip updating
        return 1;
}

void skip_entry(Directory *to, Entry *fentry) {
        if ( S_ISDIR(entry_stat(fentry)->st_mode) ) {
	        scans.dirs_skipped++;
	        item2("Skipping firectory", to, fentry->name);
        } else {
                scans.files_skipped++;
                item2("Skipping file", to, fentry->name);
        }
}

/* Job call back to update the inode bits */
JobResult sync_metadata(Directory *not_used, Entry *fentry, Directory *to, const char *target, off_t offset) {
        int ret=0;
        set_thread_status(file_path(to, target),"metadata");

        int dfd=dir_open(to);
        if (dfd==-1) {
                show_error("open()", dir_path(to));
                goto fail; 
        }
        if (target==NULL) {
                target="."; // Target the directory itself. 
        }

        /* Lookup the current inode state. It might have changed during copying and file creation. */
        struct stat to_stat;
        if (fstatat(dfd, target, &to_stat, AT_SYMLINK_NOFOLLOW )<0) {
                write_error("sync_metadata can't stat target (fstatat)", to, target);
                goto fail;
        }

        /* Check if we need to update UID and GID */
        uid_t uid=-1;
        gid_t gid=-1;
        if (preserve_owner && to_stat.st_uid != entry_stat(fentry)->st_uid) {
                uid=entry_stat(fentry)->st_uid;
        }
        if (preserve_group && (to_stat.st_gid != entry_stat(fentry)->st_gid) ) {
                gid=entry_stat(fentry)->st_gid;
        }
        if (uid!=-1 || gid!=-1) {
                if (!dryrun && fchownat(dfd, target, uid, gid, AT_SYMLINK_NOFOLLOW)<0 ) {
                        if (errno==EPERM) {
                                // Only warn about chown EPERM errors, user might not be root
                                if (atomic_load(&opers.chown_warned)==0) {
                                        show_error("fchownat() returned EPERM. Skipping rest of fchownat() errors:", file_path(to, target));
                                }
                                atomic_fetch_add(&opers.chown_warned, 1);
                        } else {
                                write_error("fchownat()", to, target);
                        }
                } else {
                        item("chown", to, target);
                        atomic_fetch_add(&opers.chown,1);
                }
        }

        // Permission bits
        if (preserve_permissions && 
                !S_ISLNK(entry_stat(fentry)->st_mode) &&
                entry_stat(fentry)->st_mode!=to_stat.st_mode) {

                // Masked mode bits
                mode_t masked_mode = entry_stat(fentry)->st_mode & (S_ISUID | S_ISGID | S_ISVTX | S_IRWXU | S_IRWXG | S_IRWXO);

                if (!dryrun && fchmodat(dfd, target, masked_mode, AT_SYMLINK_NOFOLLOW)) {
                        // fchmodat() failed: it can fail with ENOTSUPPORTED. Try again with fchmod()
                        int chmodfd = -1;

                        if (S_ISFIFO(to_stat.st_mode)) {
                                fprintf(stderr, "Skipping chmod() for FIFO %s/%s\n", dir_path(to), target);
                        } else if ((chmodfd = openat(dfd, target, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)) >= 0 &&
                                   fchmod(chmodfd, masked_mode) == 0) {
                                /* Second attempt succeeded via fd-based fchmod(). */
                                item("chmod", to, target);
                                atomic_fetch_add(&opers.chmod, 1);
                        } else {
                                write_error("fchmodat()", to, target);
                                ret = -1;
                        }
                        if (chmodfd >= 0) close(chmodfd);
                } else {
                        item("chmod", to, target);
                        atomic_fetch_add(&opers.chmod,1);
                }
        }
                
        // Access times
        if ( (preserve_time||atime_preserve) ) {
                struct timespec tmp[2] = {
                        { .tv_sec=0, .tv_nsec=UTIME_NOW },
                        { .tv_sec=0, .tv_nsec=UTIME_NOW }
                };
                tmp[0]=to_stat.st_atim;
                tmp[1]=to_stat.st_mtim;

                if (atime_preserve) tmp[0]=entry_stat(fentry)->st_atim;
                if (preserve_time) tmp[1]=entry_stat(fentry)->st_mtim;

                if (
                        to_stat.st_atim.tv_sec == tmp[0].tv_sec &&
                        to_stat.st_atim.tv_nsec == tmp[0].tv_nsec &&
                        to_stat.st_mtim.tv_sec == tmp[1].tv_sec &&
                        to_stat.st_mtim.tv_nsec == tmp[1].tv_nsec 
                ) {
                        /* skip, times were right */
                } else if (!dryrun && utimensat(dfd, target, tmp, AT_SYMLINK_NOFOLLOW)<0) {
                        if (S_ISLNK(entry_stat(fentry)->st_mode)) {
                                // Filesystem may not support utimensat() on symlinks
                                show_error_dir("Warning: utimensat() failed for symlink. Ignoring this.", to, target);
                        } else {
                                write_error("utimensat", to, target);
                                ret=-1;
                        }
                } else {
                        if (itemize) item("touch", to, target);
                        atomic_fetch_add(&opers.times,1);
                }
        }

        if (S_ISDIR(entry_stat(fentry)->st_mode) && sync_tag) {
                if (!dryrun) {
                        int fd=openat(dfd, target, O_RDONLY|O_DIRECTORY);
                        if (fd<0) {
                                fprintf(stderr,"open %s\n", strerror(errno));
                                goto out;
                        }
                        if (fsetxattr(fd, sync_tag_name, sync_tag, strlen(sync_tag), 0)<0) {
                                write_error("fsetxattr", to, target);
                        }
                        close(fd);
                }
                item("TAG", to, target);
                atomic_fetch_add(&opers.sync_tags,1);
        }
        
        // Since this is called last for any file or directory, we count here that the file is done
        atomic_fetch_add(&scans.files_synced,1);

        out:
        dir_close(to);
        return ret;
        fail:
        ret=RET_FAILED;
        goto out;
}

// Job callback to create one target inode, directory, file, FIFO, ... 
int create_target(Directory *from, Entry *fentry, Directory *to, const char *target, off_t depth) {
        assert(from && fentry && to && target);
        const char *source=fentry->name;
        assert(source);

        int tofd=dir_open(to);
        if (tofd<0) {
                write_error("Target directory has gone away", to, target);
                return -1;
        }

        if (S_ISREG(entry_stat(fentry)->st_mode)) {
                // copy regular might submit jobs
                copy_regular(from, fentry, to, target, -1);
                goto out;
        }

        set_thread_status(file_path(to,target),"create");

        if (S_ISDIR(entry_stat(fentry)->st_mode)) {
                goto out;
    
        } else if (S_ISLNK(entry_stat(fentry)->st_mode)) {
        	if (!preserve_links) goto out;
	        item("ln -s",to,target);
	        if (!dryrun && symlinkat(fentry->link,tofd,target)<0) {
                        write_error("symlinkat", to, target);
                        goto fail;
                } else {
	                atomic_fetch_add(&opers.symlinks_created, 1);
	        }

        } else if (S_ISSOCK(entry_stat(fentry)->st_mode)) {
                if (opers.sockets_warned==0) {
                        show_error_dir("Sockets are ignored. Only first socket found is reported.", from,fentry->name);
                }
                atomic_fetch_add(&opers.sockets_warned, 1);
                goto out;

        } else if (S_ISFIFO(entry_stat(fentry)->st_mode)) {
	        if (!preserve_devices) return 0;
                if (!dryrun && mkfifoat(tofd, target,
                        entry_stat(fentry)->st_mode & 0777)<0) {
                        write_error("mkfifo", to, target);
                        goto fail;
	        } else  {
                        atomic_fetch_add(&opers.fifos_created, 1);
                        item("mkfifo" ,to,target);
                }

        // Don't bother with device special files 
        } else if (S_ISCHR(entry_stat(fentry)->st_mode) || S_ISBLK(entry_stat(fentry)->st_mode)) {
                if (opers.devs_warned==0) {
                        show_error_dir("Ignoring device. Only first device is reported.", from, fentry->name);
                }
                atomic_fetch_add(&opers.devs_warned, 1);
                goto out;
        } else {
	        show_error_dir("Unknown file type ignored in dir", from, fentry->name);
                goto out;
        }

        /* If we are here a job was not started and metadata can be synced now */
        sync_metadata(NULL, fentry, to, target, 0);

        int ret=0;
        out: 
        dir_close(to);
        return ret;
        fail:
        ret=1;
        goto out;
}

JobResult sync_files(Directory *from, Entry *parent_fentry, Directory *to, const char *target, off_t offset);

JobResult sync_remove(Directory *from, Entry *parent_fentry, Directory *to, const char *target, off_t depth) {
        // If --delete clear out target directory of files which do not exist in from
        if (delete) {
                set_thread_status(dir_path(from), "deleting files");
                for(int to_i=0; to && to_i < to->entries; to_i++) {
	                if ( directory_lookup(from,to->array[to_i].name)==NULL) {
                                if (entry_isdir_i(to, to_i)) {
                                        submit_job_first(NULL, &to->array[to_i], to, NULL, depth+1, remove_hierarchy);
                                } else {
	                                unlink_entry(to, dir_entry(to, to_i));
                                }
                        }
                }
	}
        return RET_OK;
}

JobResult sync_directory(Directory *from_parent, Entry *parent_fentry, Directory *to_parent, const char *target, off_t depth) {
        Directory *to=NULL;
        assert(parent_fentry);

        set_thread_status(file_path(to_parent, target), "sync dir");

        // Check if we have already tagged the target directory and can just skip everything
        if (to_parent && sync_tag) {
                int fd=dir_openat(to_parent, target);
                if (fd>=0) {
                        char buf[256];
                        size_t s=fgetxattr(fd, sync_tag_name, buf, sizeof(buf));
                        if (s == strlen(sync_tag) && memcmp(sync_tag,buf,s)==0 ) {
                                if (itemize>1) item("# tagged", to_parent, target);
                                scans.dirs_skipped++;
                                close(fd);
                                return 0;
                        }
                }
                close(fd);
        }

        Directory *from=read_directory(from_parent, parent_fentry);
        if (!from) {
                item2("# skipping non readable diretory", from_parent, parent_fentry->name);
                atomic_fetch_add(&opers.read_errors, 1);
                return RET_FAILED;
        }

        // Create new target directory if it does not exist.
        int tofd=-1;
        if (to_parent) {
                struct stat target_stat;
                tofd=dir_open(to_parent);
                if (tofd<0) {
                        write_error("Can't open parent directory", to_parent, ".");
                        goto fail;
                }
                if (fstatat(tofd, target, &target_stat, AT_SYMLINK_NOFOLLOW)==0) {
                        if ( target_stat.st_ino == source_stat.st_ino && target_stat.st_dev == source_stat.st_dev ) {
                                /* Attempt to recurse into source directory */
                                show_warning("skipping source directory", file_path(to_parent, target));
                                skip_entry(from_parent, parent_fentry);
                        }

                        if (!S_ISDIR(target_stat.st_mode) ) {
                                // Target exists and is not a directory
                                if (delete) {
                                        unlink_file(to_parent, target);
                                } else {
                                        errno=ENOTDIR;
                                        write_error("Existing target is not a directory and --delete is not in use:", to_parent, target);
                                        dir_close(to_parent);
                                        goto fail;
                                }
                        }
                }
                if (errno==ENOENT || (!S_ISDIR(target_stat.st_mode)) ) {
                        if (!dryrun && (mkdirat(tofd, target, 0777 )<0) ) {
                                write_error("mkdir", to_parent, target);
                                goto fail;
                        } else {
                                atomic_fetch_add(&opers.dirs_created, 1);
                                item("mkdir", to_parent, target);
                        }
                }

                if (tofd>0) dir_close(to_parent);
        }

        // We always have a parent_fentry, since that is where we are copying files from,
        // but the directory we are copying to might just be created or in case of --dry-run not exist
        // FIXME this is a memory leak
        Entry *parent_tentry=(to_parent) ? directory_lookup(to_parent, target) : NULL;
        if (parent_tentry==NULL) {
                parent_tentry=my_calloc(1,sizeof(Entry));
                init_entry(parent_tentry, dir_open(to_parent), my_strdup(target));
                dir_close(to_parent);
        }
        to=read_directory(to_parent, parent_tentry);
        if (!to) {
                read_error("read_directory", to_parent, parent_tentry->name);
                item("# directory read failed", to_parent, target);
                goto fail;
        }
        assert(parent_tentry->dir);

        // We are ready to submit more sync_directory jobs
        if (recursive) {
                set_thread_status(dir_path(to), "submitting jobs");

                for(int i=0; i<from->entries; i++) {
                        if (entry_isdir_i(from ,i)) {
                                Entry *fentry=dir_entry(from,i);
                                char *target=fentry->name;
                                int dfd=dir_open(from);
                                if (dfd>=0) {
                                        init_entry(fentry, dfd, target);
                                } else {
                                        read_error("dir_open", from, fentry->name);
                                        item("# directory open failed", from, fentry->name);
                                        opers.read_errors++;
                                        continue;
                                }
                                dir_close(from);

                                // Should the target dir be excluded
                                if (should_exclude(from, fentry)) {
                                        skip_entry(to, fentry);
                                        continue;
                                }

                                if (one_file_system && from->parent && entry_stat(fentry)->st_dev!=dir_stat(from->parent)->st_dev) {
	                                // On different file system and --one_file_system was given
                                        skip_entry(to, fentry);
                                        continue;
                                }

                                if (entry_stat(fentry)->st_ino == target_root.stat.st_ino &&  entry_stat(fentry)->st_dev == target_root.stat.st_dev ) {
	                                // Attempt to recurse into target directory
                                        show_warning("skipping target directory", file_path(from, target));
	                                skip_entry(to, fentry);
                                        continue;
                                }

                                // Now we can submit the depth+1 job
                                atomic_fetch_add(&scans.read_directory_jobs, 1);
                                submit_job_first(from, fentry, to, target, depth+1, sync_directory);
                        }
                }
        }

        // Read directory part had ended.
        atomic_fetch_add(&scans.read_directory_jobs, -1);

        // File remove can be done in another thread
        if (delete) submit_job_first(from, parent_fentry, to, target, 0, sync_remove);

        // Ready to sync files now.
        if (scans.read_directory_jobs < threads/2) {
                // Try to strike a balance between sync_directory() and sync_files jobs
                submit_job(from, parent_fentry, to, target, 0, sync_files);
        } else {
                submit_or_run_job(from, parent_fentry, to, target, 0, sync_files);
        }
fail:
        if (from) d_freedir(from);
        if (to) d_freedir(to);

        return 0;
}

JobResult sync_files(Directory *from, Entry *parent_fentry, Directory *to, const char *target, off_t offset) {
        int tolen=strlen(target);
        char todir[MAXLEN];

        strncpy(todir,target,sizeof(todir)-1);

        from=scan_directory(from);
        if (from==NULL) {
                read_error("scan_directory", from, ".");
                item("# source directory scan failed", from, ".");
	        opers.read_errors++;
                return RET_FAILED;
        }

        to=scan_directory(to);
        if (to==NULL) {
                read_error("scan_directory", to, ".");
                item("# targetdirectory scan failed", to, ".");
                return RET_FAILED;
        }

        // Loop through the source directory and check for changes
        for(int i=0; i<from->entries; i++) {
	        Entry *fentry=&from->array[i];
	        Entry *tentry=NULL;

                if (fentry->state == ENTRY_FAILED) {
                        item("# File has gone away\n", from, fentry->name);
                        atomic_fetch_add(&opers.read_errors, 1);
                        continue;
                }
	    
	        /* Check if this entry should be excluded */
	        if (should_exclude(from,fentry)) {
                        skip_entry(to,fentry);
                        continue;
                }

                set_thread_status(file_path(to, fentry->name), "sync entry");

	        snprintf(todir+tolen,MAXLEN-tolen,"/%s",fentry->name);

	        /* Lookup the existing file */
	        if (to) tentry=directory_lookup(to,todir+tolen+1);

                // Check if we should just make a hard link
                if (check_hard_link(from, fentry, to, tentry)) {
                        // Hard link was created. Continue
                        continue;
                }

                // Check for filetype mismatch between source and existing target
                if (tentry) {
                        mode_t fentry_type = entry_stat(fentry)->st_mode & S_IFMT;
                        mode_t tentry_type = entry_stat(tentry)->st_mode & S_IFMT;
                        if (fentry_type != tentry_type) {
                                // Filetype mismatch: source and target are different types
                                if (delete && S_ISDIR(tentry_type)) {
                                        remove_hierarchy(NULL, tentry, to, NULL, 0);
                                } else if (delete) {
                                        unlink_entry(to, tentry);
                                } else {
                                        write_error("A different type of file is in the way. Consider --delete", to, tentry->name);
                                        continue;
                                }
                        }
                }

	        // Check if the already existing target entry: keep it, update it or remove it
	        if (tentry) {
                        if (entry_changed(fentry, tentry)) {
                                // Target entry exists but needs sync or removing
                                if (S_ISREG((entry_stat(tentry)->st_mode))) {
                                        // Updating an existing file
                                        atomic_fetch_add(&opers.files_updated,1);
                                } else if (S_ISLNK(entry_stat(tentry)->st_mode)) {
                                        // Target is a symlink
                                        if (S_ISLNK(entry_stat(fentry)->st_mode) && strcmp(fentry->link,tentry->link)==0) {
                                                // Source is the same symlink, but metadata has changed
                                                if (itemize>1) item("# symlink ok", to, tentry->name );
                                                sync_metadata(from, fentry, to, tentry->name, 0);
                                                continue;
                                        } else if (delete) {
                                                unlink_entry(to, tentry); // Unlink symlink
                                        } else {
                                                write_error("Symlink is in the way. Consider --delete", to, tentry->name);
                                                continue;
                                        }
                                } else if (!S_ISDIR(entry_stat(tentry)->st_mode)) {
                                        // Target is some other file type.
                                        if (delete) {
                                                unlink_entry(to, tentry);
                                        } else {
                                                write_error("File is in the way. Consider --delete", to, tentry->name);
                                                continue;
                                        }
                                }

	                } else {
                                // The target entry was found and is up to date
                                atomic_fetch_add(&scans.files_synced,1);
		                item2("OK", to, tentry->name);
                                continue;
	                }
	        }

                if (!delete_only) {
                        submit_or_run_job(from, fentry, to, fentry->name, i, create_target);
                }
        }

        /* Job to set the directory metadata bits needs to wait for all create jobs to have finished */
        submit_job(from, parent_fentry, to, NULL, DSYNC_DIR_WAIT, sync_metadata);

        return 0;
}

int main(int argc, char *argv[]) {

    memset(&scans,0,sizeof(scans));
    memset(&opers,0,sizeof(opers));

    /* Check the options */
    parse_options(argc, argv);
    static_argv=argv;
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
    
        // Open source and target directories
        int sfd=dir_openat(NULL, argv[optind]);
        if (sfd<0) {
                fprintf(stderr,"Open source directory'%s': %s", argv[optind], strerror(errno));
                exit(1);
        }
        int tfd=dir_openat(NULL, argv[optind+1]);
        if (tfd<0) {
                fprintf(stderr,"Open target directory '%s': %s\n",argv[optind+1],strerror(errno));
                exit(1);
        }
        fstat(sfd, &source_stat);
        fstat(tfd, &target_root.stat);

        // Record the starting timestamp
        clock_gettime(CLOCK_BOOTTIME,&scans.start_clock_boottime);

        // Init the static source and target
        // FIXME: this should be removed.
        if (! realpath(argv[optind], s_frompath)) {
                fprintf(stderr,"Can't resolve source path '%s': %s\n", argv[optind], strerror(errno));
                exit(1);
        }
        if (! realpath(argv[optind+1], s_topath)) {
                fprintf(stderr,"Can't resolve target path '%s': %s\n", argv[optind+1], strerror(errno));
                exit(1);
        }
        if (fchdir(tfd)<0) {
               fprintf(stderr,"chdir('%s'): %s\n",argv[optind],strerror(errno));
               exit(1);
        }

        memset(&source_root, 0, sizeof(source_root));
        init_entry(&source_root, sfd, s_frompath);

        // start the threads, job queue and wait the submitted job to finish
        atomic_fetch_add(&scans.read_directory_jobs, -1);
        submit_job(NULL, &source_root, NULL, s_topath, 0, sync_directory);
        start_job_threads(threads);

        // Finished. Show all the stats
        if (progress>=1) {
                print_progress(); // One last fime
        }

        if (stats>0) print_opers(stdout, &opers);
        if (stats>1) print_scans(&scans);

        if (opers.error_espace && !delete_only) {
	        show_warning("WARNING: Out of space (ESPACE).",NULL);
        }
        if (opers.read_errors) {
                fprintf(stderr,"WARNING: There was read errors!\n");
        }
        if (opers.write_errors) {
	        fprintf(stderr,"WARNING: There was write errors!\n");
        }
        int ret=0;
        if (opers.read_errors>0 || opers.write_errors>0)  {
                ret=2; // Return 2 if there was any errors
        } else {
                Opers dummy;
                memset(&dummy,0,sizeof(dummy));
                if (memcmp(&dummy,&opers,sizeof(dummy))==0) {
                        if (!quiet) fprintf(stderr, "# No changes to any files.\n");
                } else {
                        if (!quiet) fprintf(stderr, "# Some files were changed.\n");
                        ret=1;  // --dryrun returns 1 if there was changes
                }
        }

        if (!quiet) {
                time_t now = time(NULL);
                struct tm *t = localtime(&now);
                char buf[64];

                strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", t);
                printf("# Pdsync %s finished at %s with status %d\n",VERSION, buf,ret);
        }

        return ret;
}
