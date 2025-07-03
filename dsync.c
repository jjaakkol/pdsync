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

#define VERSIONNUM "1.9"
#define VERSION VERSIONNUM "-" MODTIME

static char* const *static_argv;
static int dryrun=0;
static int delete=0;
static int delete_only=0;
static int one_file_system=0;
static int atime_preserve=0;
static int itemize=0;
static int quiet=0;
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
static int check=1;
int privacy=0;
int progress=0;
static int threads=4;
int debug=0;
const char *sync_tag=NULL;
const char *sync_tag_name="user.pdsync";

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
static struct stat target_stat;
static struct stat source_stat;

typedef struct {
    int dirs_created;
    int files_copied;
    atomic_int files_updated;
    int entries_removed;
    int dirs_removed;
    atomic_llong bytes_copied;
    atomic_llong sparse_bytes;
    int symlinks_created;
    int sockets_created;
    int fifos_created;
    int devs_created;
    int hard_links_created;
    int read_errors;
    atomic_int a_write_errors;
    int no_space;
    int chown;
    int chmod;
    int times;
    int items;
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

enum { 
        ATIME_PRESERVE=255, 
        PRIVACY=256, 
        DELETE_ONLY=257,
        THREADS=258,
        SYNC_TAG=259,
        SYNC_TAG_NAME=260,
        DEBUG=261,
        CHECK=262
};


static struct option options[]= {
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
        { NULL, 0, NULL, 0 }       
};

int dsync(Directory *from_parent, Entry *parent_fentry, Directory *to_parent, const char *target, off_t offset);

static void show_version() {
    printf("pdsync "VERSION" (C) 09.2000 - 05.2025 Jani Jaakkola (jani.jaakkola@helsinki.fi)\n");
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
    putchar('\n');
}


void write_error(const char *why, const Directory *d, const char *file) {
        atomic_fetch_add(&opers.a_write_errors, 1);
        if (errno==ENOSPC && !delete) {
                fprintf(stderr, "Out of space. Consider --delete to remove files.\n");
                opers.no_space++;
        }
        fprintf(stderr,"Write error: %s %s%s: %s\n",
                why,
                (privacy) ? "[PRIVATE]":dir_path(d), file,
                (errno==0) ? "" : strerror(errno));
        fprintf(stderr,"Exiting immediately.\n");
        exit(2);
}

void show_error(const char *why, const char *file) {
    if (errno==ENOSPC) {
	opers.no_space++;
    }
    fprintf(stderr,"Error: %s %s: %s\n",why,
	    (privacy) ? "[PRIVATE]":file,
	    (errno==0) ? "" : strerror(errno));
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

static void item(const char *i, const Directory *d, const char *name ) {
        FILE *stream=stdout;
        opers.items++;
        if (!itemize) return;
        fprintf(stream,"%s: %s%s\n",i,dir_path(d),name);
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
                        if (!optarg[0] || *endptr || threads<1 || threads > 256 ) {
                                fprintf(stderr,"Invalid value given to --threads: '%s'\n",optarg);
                                exit(1);
                        }
                        break;
                }
        case SYNC_TAG_NAME: sync_tag_name=optarg; break;
        case SYNC_TAG: sync_tag=optarg; break;
        case DEBUG: debug++; fprintf(stderr,"Debug: %d\n",debug); break; 
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
    if (scans->dirs_skipped) {
	printf("%8d directories skipped\n",scans->dirs_skipped);
    }
    if (scans->files_skipped) {
        printf("%8d files skipped\n",scans->files_skipped);
    }
    if (scans->jobs) {
        printf("%8d total number of jobs run\n", scans->jobs);
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
    if (scans->read_directory_jobs) {
	printf("%8d read directory jobs queued\n",scans->read_directory_jobs);
    }
    if (scans->read_directory_miss) {
	printf("%8d read directory misses\n",scans->read_directory_miss);
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
    if (scans->pre_scan_too_late>0) {
        printf("%8d directory prescan too late\n",
               scans->pre_scan_too_late);
    }
    if (scans->pre_scan_dirs) {
	printf("%8d prescanned directorys\n",scans->pre_scan_dirs);
    }	
    if (scans->pre_scan_allocated) {
	printf("%8d allocated prescan entries\n",scans->pre_scan_allocated);
    }	
    if (scans->pre_scan_used!=scans->pre_scan_allocated) {
	printf("%8d unused prescan entries\n",
	       scans->pre_scan_allocated-scans->pre_scan_used);
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
                fprintf(stream, "%8d directories created\n", stats->dirs_created);
        }
    if (stats->dirs_removed) {
        fprintf(stream, "%8d directories removed\n", stats->dirs_removed);
    }
    if (stats->entries_removed) {
        fprintf(stream, "%8d entries removed\n", stats->entries_removed);
    }
    if (stats->files_copied) {
        fprintf(stream, "%8d files copied, %.1ff/s\n", stats->files_copied,
                stats->files_copied*1000000000.0/ns);
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
        fprintf(stream, "%8d symlinks created\n", stats->symlinks_created);
    }
    if (stats->hard_links_created) {
        fprintf(stream, "%8d hard links created\n", stats->hard_links_created);
    }
    if (stats->sockets_created) {
        fprintf(stream, "%8d sockets created\n", stats->sockets_created);
    }
    if (stats->fifos_created) {
        fprintf(stream, "%8d fifos created\n", stats->fifos_created);
    }
    if (stats->devs_created) {
        fprintf(stream, "%8d devs created\n", stats->devs_created);
    }
    if (stats->chown) {
        fprintf(stream,"%8d file owner/group changed\n", stats->chown);
    }
    if (stats->chmod) {
        fprintf(stream,"%8d file chmod bits changed\n", stats->chown);
    }
    if (stats->times) {
        fprintf(stream,"%8d file atime/mtime changed\n", stats->chown);
    }
    if (stats->read_errors) {
        fprintf(stream, "%8d errors on read\n", stats->read_errors);
    }
    if (stats->a_write_errors) {
        fprintf(stream, "%8d errors on write\n", stats->a_write_errors);
    }
}

/* Print the progress to ttysream, obeying privacy options. Called from a thread once a second, with mutex locked */
void print_progress() {
        static int last_synced=0;
        static long long last_bytes;
        static long long last_ns=0;

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
        int files_synced=atomic_load(&scans.files_synced);
        int files_total=(source_root.dir) ? atomic_load(&source_root.dir->descendants) + source_root.dir->entries : 0;
        fprintf(tty_stream, "PG %02lld:%02lld:%02lld | ", s / 3600LL, (s / 60LL) % 60, s % 60LL );                
        fprintf(tty_stream,"%d/%d files |%7.1ff/s |%9s |%9s/s |%5d queued|%3d idle |\n",
                files_synced,
                files_total, 
                1000000000.0 * (files_synced-last_synced) / (now_ns-last_ns),
                format_bytes(opers.bytes_copied, B),
                format_bytes( 1000000000.0L *(opers.bytes_copied-last_bytes) / (now_ns-last_ns),BpS),
                scans.queued,
                scans.idle_threads
        );
        if (progress>=2) print_opers(tty_stream,&opers);
        if (progress>=3) print_scans(&scans);
        if (progress>=4) print_jobs(tty_stream);
 
        last_synced=files_synced;
        last_bytes=opers.bytes_copied;
        last_ns=now_ns;
}

int remove_hierarchy(Directory *parent, Entry *tentry) {
        struct stat thisdir;
        Directory *del=NULL;
        int i;
 
        del=pre_scan_directory(parent, tentry);
        if (!del) {
                item("ERROR", parent, tentry->name);
                goto fail;
        }
        int dfd=dir_open(del);
        if (dfd<0) goto fail;
        fstat(dfd,&thisdir);
        if (thisdir.st_dev==source_stat.st_dev &&
        	thisdir.st_ino==source_stat.st_ino) {
        	/* This can happen when doing something like 
	        * dsync /tmp/foo/bar /tmp/foo */
        	show_warning("Skipping removal of source directory", dir_path(parent));
	        goto fail;
        }
        if (thisdir.st_dev==target_stat.st_dev &&
	        thisdir.st_ino==target_stat.st_ino) {
	        /* This should only happen on badly screwed up filesystems */
	        show_warning("Skipping removal of target directory (broken filesystem?).\n", dir_path(parent));
	        goto fail;
        }
  
        for(i=0;i<del->entries;i++) {
                struct stat file;
                set_thread_status(file_path(parent, del->array[i].name), "unlinking");
                if (fstatat(dfd,del->array[i].name,&file,AT_SYMLINK_NOFOLLOW)<0) {
                        write_error("fstatat", del, del->array[i].name);
                        goto fail;
                }
                if (S_ISDIR(file.st_mode)) {
                        if (remove_hierarchy(del, &del->array[i])<0) goto fail;
                } else if (!dryrun && unlinkat(dfd,del->array[i].name,0)<0) {
                        write_error("unlinkat", del, del->array[i].name);
                        goto fail; 
                }
                item("RM",del,del->array[i].name);
		opers.entries_removed++;
	}

        item("RD", parent, tentry->name);
        int pfd=-1;
        if (!dryrun) {
                pfd=dir_open(parent);
                if (unlinkat(pfd, tentry->name, AT_REMOVEDIR )<0) {
	                write_error("rmdir", parent, tentry->name);
                        goto fail; 
                }
        }
        opers.dirs_removed++;

        int ret=0;
 cleanup:
        if (dfd>=0) dir_close(del);
        if (pfd>=0) dir_close(parent);
        if (del) d_freedir(del);
        return ret;

 fail:
        write_error("remove_hierarchy", del, tentry->name);
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
        const size_t copy_job_size = 16 * 1024 * 1024;
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

int copy_regular(Directory *from, Entry *fentry, Directory *to, const char *target, off_t offset) {
        int fromfd=-1;
        int tofd=-1;
        int to_dfd=-1;
        struct stat from_stat;
        int sparse_copy=preserve_sparse; // FIXME: do we need this?
        int ret=0;
        off_t copy_job_size=16*1024*1024;
        char buf[32];

        assert(from && to && fentry);
        const char *source=fentry->name;
        assert(source && target);

        int from_dfd = dir_open(from);
        fromfd=openat(from_dfd, source, O_RDONLY|O_NOFOLLOW);
        if (fromfd<0 || fstat(fromfd,&from_stat)) {
                show_error_dir("open", from, source);
                goto fail; 
        }
        if (dryrun) {
                item("CP",to,target);
                opers.bytes_copied+=from_stat.st_size;
                goto end;
        }
        to_dfd = dir_open(to);
        tofd=openat(to_dfd, target, O_RDWR|O_CREAT|O_NOFOLLOW, 0666); // mmap() IO needs RDWR access
        if(tofd<0) {
                write_error("open", to, target);
                goto fail;
        }

        int num_jobs= (from_stat.st_size + copy_job_size - 1) / copy_job_size;

        /* offset -1 means that this is the first job operating on this file */
        if (offset==-1) {
                set_thread_status(file_path(to,target),"ftruncate");

                /* Check for sparse file */
                if ( from_stat.st_size > (1024*1024) && from_stat.st_size/512 > from_stat.st_blocks ) {
	                static int sparse_warned=0;
	                if (!sparse_warned && !preserve_sparse) {
	                        show_warning("Sparse or compressed files detected. Consider --sparse option",source);
                                sparse_warned++;
                        }
	        }

                // Truncate the file to the desired size, except if we know it already is right size
                Entry *tentry=directory_lookup(to, target);
                if (!tentry || tentry->stat.st_size!=from_stat.st_size) {
                        if (ftruncate(tofd, from_stat.st_size) < 0) {
                                write_error("ftruncate", to, target);
                                goto fail;
                        }
                }

                /* Submit the actual copy jobs */
                if (from_stat.st_size==0) {
                        goto end; // Zero size file, we are done
                } else if (from_stat.st_size<=16*1024) {
                        offset=0; // We have the file open and it is small. Copy it ourselves
                } else {
                        for (int i=0; i<num_jobs; i++) {
                                // Optimization: if already have a long queue, don't go through submit and it's locks. 
                                if (scans.idle_threads==0 && scans.queued > threads * 10) {
                                        copy_regular(from, fentry, to, target, copy_job_size*i);
                                } else {
                                        submit_job(from, fentry, to, target, copy_job_size*i, copy_regular);
                                }
                        }
                        goto end;
                }
        }

        if (update_all || check) {
                if (sparse_copy) {
                        snprintf(buf,sizeof(buf)-1,"update mmap %ld", offset/copy_job_size);
                        set_thread_status(file_path(to,target),buf);
                        if (copy_regular_mmap(fromfd, tofd, from_stat.st_size, offset)<0) {
                                write_error("copy_regular_mmap", to, target);
                        }
                } else {
                        snprintf(buf,sizeof(buf)-1,"update rw %ld", offset/copy_job_size);
                        set_thread_status(file_path(to,target),buf);
                        copy_regular_rw(fromfd, tofd, from_stat.st_size, offset);
                }
        } else {
                snprintf(buf,sizeof(buf)-1,"sendfile %ld", offset/copy_job_size);
                set_thread_status(file_path(to,target),buf);

	        // Simple loop with option to seek a hole and punch hole to target
                int w=0;
                if ( lseek(fromfd,offset,SEEK_SET)<0 || lseek(tofd,offset,SEEK_SET)<0 ) {
                        write_error("lseek", to, target);
                        goto fail;
                }
                off_t written=0;
                off_t to_copy=(offset + copy_job_size > from_stat.st_size) ? from_stat.st_size-offset : copy_job_size;
                while(written<to_copy) {
                        off_t chunk=to_copy-written;

                        // If sparse_copy check for holes
                        if (sparse_copy) {
                                off_t hole=lseek(fromfd, offset+written, SEEK_HOLE);
                                if (hole==offset+written) {
                                        // Found a hole. Punch a hole to target
                                        off_t data=lseek(fromfd, hole, SEEK_DATA);
                                        w=data-hole; 
                                        if (fallocate(tofd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, offset, w)<0) {
                                                fprintf(stderr,"fallocate(FALLOC_PUNCH_HOLE,%d): %s", w, strerror(errno));
                                        } else {
                                                // FIXME: Need to write zero's to target
                                        }
                                        atomic_fetch_add(&opers.sparse_bytes, w);
                                        written+=w;
                                        lseek(tofd, offset+written, SEEK_SET);
                                }
                                // Move pointer back to the data and count the next copy chunk size
                                lseek(fromfd, offset+written, SEEK_SET);
                                chunk=hole-(offset+written);
                                if (written+chunk > to_copy) chunk=to_copy-written; 
                        } 
                        // Just copy the data 
                        if ( (w=sendfile(tofd,fromfd,NULL,chunk) )>0) {
                                atomic_fetch_add(&opers.bytes_copied,w);
                                written+=w;
                        }
                }
	        if (w<0) {
                        write_error("write", to, target);
                        goto fail;
        	}
        }

        if (offset/copy_job_size == num_jobs-1) {
                // This is the last job
                item("CP",to,target);
                opers.files_copied++;
        }

        end:
        if (offset>=0) {
                snprintf(buf,sizeof(buf)-1,"copy %ld done", offset/copy_job_size);
                set_thread_status(file_path(to,target),buf);
        } else set_thread_status("copy submit", file_path(to,target));
        if (fromfd>=0) close(fromfd);
        if (from_dfd>=0) dir_close(from);
        if (tofd>=0) close(tofd);
        if (to_dfd>=0) dir_close(to);

        return ret;
 fail:
        item("ERROR", from, target);
        fentry->state=ENTRY_FAILED;
        ret = RET_FAILED;
        goto end;
}

/* Remove one entry from a directory */
int remove_entry(Directory *parent, Entry *tentry) {
        int ret=0;
        const char *name=tentry->name;
        if (S_ISDIR(tentry->stat.st_mode)) {
                remove_hierarchy(parent, tentry);
        } else {
                item("RM",parent,name);
                int dfd=dir_open(parent);
                if (!dryrun && unlinkat(dfd, name, 0)) {
                        write_error("unlink", parent, name);
                        ret=-1;
                } else opers.entries_removed++;
                dir_close(parent);
        }
        tentry->state=ENTRY_DELETED; // FIXME: this needs a lock
        return ret;
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

/* Remove missing files and directories which exist in to but not in from */
int remove_old_entries(Directory *from,
		       Directory *to) {
    int to_i=0;

    for(to_i=0; to && to_i < to->entries; to_i++) {	
	if ( directory_lookup(from,to->array[to_i].name)==NULL) {
	    /* Entry no longer exists in from and should be removed if --delete is in effect */
	    remove_entry(to, &to->array[to_i]);
	}
    }
    return 0;
}

/*
 * Returns 1 if the from entry considered newer, changed or just different
 * than to entry
 */
int entry_changed(const Entry *from, const Entry *to) {
    if (from->error) {
	/* If there was problems checking the file attributes, we probably
	 * cannot access it anyway. So we return 'not changed' (and skip it).
	 */
	return 0;
    }

    if (to->error) {
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

    /* If size is different we need to at least update the file */
    if (from->stat.st_size!=to->stat.st_size) {
        return 1;
    }

    /* If we have preserve time any change in mtime is applied */
    if (preserve_time &&
                (from->stat.st_mtime!=to->stat.st_mtime ||
                from->stat.st_mtim.tv_nsec != to->stat.st_mtim.tv_nsec)) {
        return 1;
    }   

    /* If we have --atime-preserve any change in atime is applied */
    if (atime_preserve &&
                (from->stat.st_atime!=to->stat.st_atime ||
                from->stat.st_atim.tv_nsec != to->stat.st_atim.tv_nsec) ) {
        return 1;
    }

    /* If from is newer by mtime it has changed. */
    if (from->stat.st_mtime>to->stat.st_mtime) {
	return 1;
    }
    if (from->stat.st_mtime == to->stat.st_mtime &&
        from->stat.st_mtim.tv_nsec > to->stat.st_mtim.tv_nsec) {
        return 1;
    }

    /* Regular file and we have found no reason to copy it.*/
    if (S_ISREG(from->stat.st_mode) && S_ISREG(to->stat.st_mode)) {
        return 0;
    }

    /* If symlink names match don't update it. */
    if (S_ISLNK(from->stat.st_mode) && 
	S_ISLNK(to->stat.st_mode) &&
	strcmp(from->link,to->link)==0) {
	/* Symlinks do match */
	return 0;
    }

    /* fprintf(stderr,"Just different: %s %s\n",from->name,to->name); */
    /* We found no reason to skip updating */
    return 1;
}

/* FIXME: hard links don't work now */
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
                write_error("link", NULL, target);
		show_error("link",target);
		return 1;
	    }
	    if (lstat(target,&target_stat)<0 ||
		target_stat.st_ino!=l->target_ino ||
		target_stat.st_dev!=l->target_dev) {
		show_warning("hard link source changed",l->target_name);
	    }
	}
	if (itemize) {
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
        write_error("save link info lstat failed (?)", NULL, path);
	/* Should not happen (tm) */
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
    link->target_name=my_strdup(path);
    link->next=link_htable[hval];
    link_htable[hval]=link;
}

void skip_entry(Directory *to, const Entry *fentry) {
        if ( S_ISDIR(fentry->stat.st_mode) ) {
	        scans.dirs_skipped++;
	        if (itemize>2) item("SD",to,fentry->name);
        } else {
                scans.files_skipped++;
                if (itemize>2) item("SF",to,fentry->name);
        }
}

/* Job call back to update the inode bits */
JobResult sync_metadata(Directory *not_used, Entry *fentry, Directory *to, const char *target, off_t offset) {
        int ret=0;
        set_thread_status(file_path(to, target),"metadata");

        // Since this is called last for any file or directory, we count here that the file is done
        atomic_fetch_add(&scans.files_synced,1);

        int dfd=dir_open(to);
        if (dfd==-1) {
                show_error_dir("open parent", to, fentry->name);
                goto fail; 
        }

        /* Lookup the existing inode bits */
        struct stat to_stat;
        if (fstatat(dfd, target, &to_stat, AT_SYMLINK_NOFOLLOW )<0) {
                write_error("sync_metadata can't stat target (fstatat)", to, target);
                goto fail;
        }

        /* Check if we need to update UID and GID */
        uid_t uid=-1;
        gid_t gid=-1;
        if (preserve_owner && to_stat.st_uid != fentry->stat.st_uid) {
                uid=fentry->stat.st_uid;
        }
        if (preserve_group && (to_stat.st_gid != fentry->stat.st_gid) ) {
                gid=fentry->stat.st_gid;
        }
        if (uid!=-1 || gid!=-1) {
                if (!dryrun && fchownat(dfd, target, uid, gid, AT_SYMLINK_NOFOLLOW)<0 ) {
                        write_error("fchownat", to, target);
                        ret=-1;
                } else {
                        if (itemize>1) item("CO", to, target);
                        opers.chown++;
                }
        }

        // Permission bits
        if (preserve_permissions && 
                !S_ISLNK(fentry->stat.st_mode) &&
                fentry->stat.st_mode!=to_stat.st_mode) {
                if (!dryrun && fchmodat(dfd, target, fentry->stat.st_mode, AT_SYMLINK_NOFOLLOW)<0) {
                        write_error("fchmodat", to, target);
                        ret=-1;
                } else {
                        if (itemize>2) item("CH", to, target);
                        opers.chmod++;
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

                if (atime_preserve) tmp[0]=fentry->stat.st_atim;
                if (preserve_time) tmp[1]=fentry->stat.st_mtim;

                if (
                        to_stat.st_atim.tv_sec == tmp[0].tv_sec &&
                        to_stat.st_atim.tv_nsec == tmp[0].tv_nsec &&
                        to_stat.st_mtim.tv_sec == tmp[1].tv_sec &&
                        to_stat.st_mtim.tv_nsec == tmp[1].tv_nsec 
                ) {
                        /* skip, times were right */
                } else if (!dryrun && utimensat(dfd, target, tmp, AT_SYMLINK_NOFOLLOW)<0) {
                        write_error("utimensat", to, target);
                        ret=-1;
                } else {
                        if (itemize) item("TI", to, target);
                        opers.times++;
                }
        }

        if (S_ISDIR(fentry->stat.st_mode) && sync_tag) {
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
        }
        

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

        if (S_ISREG(fentry->stat.st_mode)) {
	        /* copy regular might submit jobs */
	        copy_regular(from, fentry, to, target, -1);
                /* We have a target to set the inode bits. We submit a job to set its bits */
                submit_job(from, fentry, to, fentry->name, DSYNC_FILE_WAIT, sync_metadata); // FIXME: do this in copy regular 
                goto out;
        }
        
        if (S_ISDIR(fentry->stat.st_mode)) {
                struct stat target_stat;
	        if (fstatat(tofd,target,&target_stat,AT_SYMLINK_NOFOLLOW)<0) {
                        if  (errno==ENOENT ) {
	                        item("MD",to,target);
                                set_thread_status(file_path(to,target),"mkdir");
	                        if (!dryrun && (mkdirat(tofd,target,0777)<0 || fstatat(tofd, target, &target_stat, AT_SYMLINK_NOFOLLOW)<0) ) {
                                        write_error("mkdir", to, target);
                                        goto fail;
	                        }
	                        opers.dirs_created++;
                        }
                } else if (!dryrun && !S_ISDIR(target_stat.st_mode) ) {
                        errno=ENOTDIR;
                        write_error("Existing target is not a directory", to, target);
                        goto fail;
	        }
	        if (safe_mode) {
		        if (preserve_owner && fchown(tofd,0,0)<0) {
                                write_error("fchown", to, target);
                                goto fail;
                        }
		        if (fchmod(tofd,0700)<0) {
                                write_error("chmod", to, target);
                                goto fail;
		        }
	        }
        	if (one_file_system && from->parent && fentry->stat.st_dev!=dir_stat(from->parent)->st_dev) {
	                /* On different file system and one_file_system was given */
                        skip_entry(to,fentry);
	        } else if (fentry->stat.st_ino == target_stat.st_ino &&  fentry->stat.st_dev == target_stat.st_dev ) {
	                /* Attempt to recurse into target directory */
                        show_error_dir("Skipping target directory", to, target);
	                skip_entry(to, fentry);
                } else if ( target_stat.st_ino == source_stat.st_ino && target_stat.st_dev == source_stat.st_dev ) {
	                /* Attempt to recurse into source directory */
                        show_error_dir("Skipping source directory in %s%s\n", from, target);
                        skip_entry(from, fentry);
                } else if (recursive) {
	                /* All sanity checks turned out green: we start a job to recurse to subdirectory */
                        submit_job(from, fentry, to, target, 0, dsync);
                        goto out;
	        }
    
        } else if (S_ISLNK(fentry->stat.st_mode)) {
        	if (!preserve_links) goto out;
	        item("SL",to,target);
	        if (!dryrun && symlinkat(fentry->link,tofd,target)<0) {
                        write_error("symlink", to, target);
                        goto fail;
                } else {
	                opers.symlinks_created++;
	        }

        } else if (S_ISSOCK(fentry->stat.st_mode)) {
                show_error_dir("Ignoring socket", from,fentry->name);
                goto out;

        } else if (S_ISFIFO(fentry->stat.st_mode)) {
	        if (!preserve_devices) return 0;
	        item("FI",to,target);
	        if (!dryrun && mkfifoat(tofd,target,0777)<0) {
                        write_error("mkfifo", to, target);
                        goto fail;
	        }

        // Don't bother with device special files 
        } else if (S_ISCHR(fentry->stat.st_mode)) {
                show_error_dir("Ignoring character device", from, fentry->name);
                goto out;

        } else {
	        show_error_dir("Unknown file type ignored in dir", from, fentry->name);
                goto out;
        }

        /* If we did not start a Job, we can just update the metadata now, */
        sync_metadata(from, fentry, to, target, depth);

        int ret=0;
        out: 
        dir_close(to);
        return ret;
        fail:
        ret=1;
        goto out;
}

int dsync(Directory *from_parent, Entry *parent_fentry, Directory *to_parent, const char *target, off_t offset) {
    Directory *from=NULL;
    Directory *to=NULL;
    int i;
    int ret=-1;
    int tolen=strlen(target);
    char todir[MAXLEN];

    assert(parent_fentry);

    set_thread_status(file_path(from_parent,parent_fentry->name), "sync running");
    strncpy(todir,target,sizeof(todir)-1);

    // Check if we have a already tagged directory and skip it.
    if (sync_tag) {
        int fd=dir_openat(to_parent, target);
        if (fd>=0) {
                char buf[256];
                size_t s=fgetxattr(fd, sync_tag_name, buf, sizeof(buf));
                if (s == strlen(sync_tag) && memcmp(sync_tag,buf,s)==0 ) {
                        item("TAGGED", to_parent, target);
                        scans.dirs_skipped++;
                        close(fd);
                        return 0;
                }
        }
        close(fd);
    }

    from=pre_scan_directory(from_parent, parent_fentry);
    if (from==NULL) {
        item("ERROR", from_parent, parent_fentry->name);
	opers.read_errors++;
	goto fail;
    }

    // We always have a parent_fentry, since that is where we are copying files from,
    // but the directory we are copying to might be just created.
    // FIXME this is a memory leak 
    Entry *parent_tentry=(to_parent) ? directory_lookup(to_parent, target) : NULL;
    if (parent_tentry==NULL) {
        parent_tentry=my_calloc(1,sizeof(Entry));
        init_entry(parent_tentry, dir_open(to_parent), my_strdup(target));
        dir_close(to_parent);
    }
    to=pre_scan_directory(to_parent, parent_tentry);
    if (to==NULL) {
        item("ERROR", to_parent, target);
        goto fail;
    }
    
    if (delete) remove_old_entries(from, to);

    /* Loop through the source directory entries */
    for(i=0;i<from->entries &&
	    opers.a_write_errors==0
	    ;i++) {
	Entry *fentry=&from->array[i];
	Entry *tentry=NULL;
	    
	/* Check if this entry should be excluded */
	if (should_exclude(from,fentry)) {
                skip_entry(to,fentry);
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
                    if ( S_ISREG(fentry->stat.st_mode) && S_ISREG(tentry->stat.st_mode) ) {
                        // Try to keep existing file.
                        atomic_fetch_add(&opers.files_updated,1);
                        if (itemize>1) item("KEEP", to, tentry->name );
                    } else if (delete || !S_ISDIR(tentry->stat.st_mode)) {
			/* Entry exists, but it is OK to remove it */
			remove_entry(to, tentry);
		    } else {
			write_error("Directory is in the way. Consider --delete", to, tentry->name);
			continue;
		    }
		}
	    } else {
                atomic_fetch_add(&scans.files_synced,1);
		if (itemize>=2) item("OK",to,todir);
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

            /* We could create the target in a different job, but I measured this to be faster */
            //submit_job(from, fentry, to, fentry->name, i, create_target);
            create_target(from, fentry, to, fentry->name, i);

	    /* Save paths to entries having link count > 1 
	     * for making hard links */
	    if (preserve_hard_links &&
		fentry->stat.st_nlink>1 &&
		!S_ISDIR(fentry->stat.st_mode)) {
		save_link_info(fentry,todir);		
	    }
	}

    }

        /* Job to set the directory metadata bits needs to wait for all create jobs to have finished */
        submit_job(from_parent, parent_fentry, to_parent, target, DSYNC_DIR_WAIT, sync_metadata);

    ret=0;
    int failed_jobs=0;

fail:
    set_thread_status(file_path(from_parent,parent_fentry->name), "sync done");

    if (failed_jobs>0) fprintf(stderr,"SD level %ld: %d failed subjobs.\n",offset,failed_jobs);

    if (from) d_freedir(from);
    if (to) d_freedir(to);

    todir[tolen]=0;
    return ret;
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
        if (fchdir(tfd)<0) {
	        fprintf(stderr,"chdir('%s'): %s\n",argv[optind],strerror(errno));
	        exit(1);
        }

        // Record the starting timestamp
        clock_gettime(CLOCK_BOOTTIME,&scans.start_clock_boottime);

        // Init the static source and target
        // FIXME: this should be removed.
        if (! realpath(argv[optind], s_frompath)) {
                fprintf(stderr,"Cannot resolve source path '%s': %s\n", argv[optind], strerror(errno));
                exit(1);
        }
        if (! realpath(argv[optind+1], s_topath)) {
                fprintf(stderr,"Cannot resolve target path '%s': %s\n", argv[optind+1], strerror(errno));
                exit(1);
        }
        fstat(sfd,&source_stat);
        fstat(tfd,&target_stat);

        init_entry(&source_root, sfd, s_frompath);
        Job *job=submit_job(NULL, &source_root, NULL, s_topath, 0, dsync);

        // start the threads, job queue and wait the submitted job to finish
        start_job_threads(threads, job);

    if (opers.no_space && !delete_only) {
	show_warning("Out of space. Consider --delete.",NULL);
    }
    if (opers.a_write_errors) {
	fprintf(stderr,"pdsync was canceled because of write errors.\n");
    }

    if (!quiet) {
        time_t now = time(NULL);
        struct tm *t = localtime(&now);
        char buf[64];
        tty_stream=stdout;
        print_progress();

        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", t);
        printf("Pdsync %s finished at %s\n",VERSION,buf);

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
	if (opers.read_errors==0 && opers.a_write_errors==0) {
	    /* No failures */
	    return 0;
	} else {
	    return 1;
	}
    }
    exit(0);
}
