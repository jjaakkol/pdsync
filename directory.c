#include "dsync.h"

// This file contains Entry and Directory handling

typedef struct DentStruct {
        char *name;
        ino_t d_ino;
        unsigned char d_type;
} Dent;


void show_error_dir(const char *message, const Directory *parent, const char *file)
{
        fprintf(stderr, "Error: %s : %s : %s%s\n", message, strerror(errno), dir_path(parent), file);
}


/* Initialize a directory Entry. */
Entry *init_entry(Entry *entry, int dfd, char *name)
{
        memset(entry, 0, sizeof(*entry));
        entry->name = name;

        if (fstatat(dfd, name, &entry->stat, AT_SYMLINK_NOFOLLOW) < 0)
        {
                entry->error = errno;
                show_error("fstatat", name);
        }
        else if (S_ISLNK(entry->stat.st_mode))
        {
                /* Read the symlink if there is one. FIXME: maybe skip this if we don't have --preserve-links */
                char linkbuf[MAXLEN];
                int link_len;
                if ((link_len = readlinkat(dfd, name, linkbuf, sizeof(linkbuf) - 1)) <= 0)
                {
                        /* Failed to read link. */
                        show_error("readlink", name);
                        /* FIXME: read errors is not visible here:
                        opers.read_errors++; */
                }
                else
                {
                        /* Save the link */
                        entry->link = my_malloc(link_len + 1);
                        memcpy(entry->link, linkbuf, link_len);
                        entry->link[link_len] = 0;
                }
        }
        scans.entries_scanned++;
        entry->state=ENTRY_INIT;
        return entry;
}

const char *dir_path(const Directory *d)
{
        _Thread_local static char buf[MAXLEN];
        _Thread_local static int len;
        if (d)
        {
                assert(d->magick==0xDADDAD);
                dir_path(d->parent);
                if (privacy && d->parent && d->parent->parent_entry &&
                    d->parent->parent_entry->stat.st_uid != 0 && d->stat.st_uid != getuid())
                {
                        len += snprintf(buf + len, MAXLEN - len, "[0x%lx]/", d->stat.st_ino);
                }
                else
                {
                        len += snprintf(buf + len, MAXLEN - len, "%s/", d->name);
                }
        }
        else
                len = snprintf(buf, MAXLEN, "%s", "");
        return buf;
}

const char *file_path(const Directory *d, const char *f)
{
        _Thread_local static char buf[MAXLEN];
        if (privacy && d && d->parent_entry && d->stat.st_uid != 0 && d->stat.st_uid != getuid())
        {
                snprintf(buf, sizeof(buf), "%s%s", dir_path(d), "[PRIVACY]");
        }
        else
        {
                snprintf(buf, sizeof(buf), "%s%s", dir_path(d), f);
        }
        return buf;
}

/* gets a file handle to Directory, possibly reopening it */
int dir_open_unlocked(Directory *d)
{
        if (d->fd < 0)
        {
                int fd = dir_openat(d->parent, d->name);
                struct stat s;
                if (fd < 0 || fstat(fd, &s) < 0 ||
                    s.st_ino != d->stat.st_ino ||
                    s.st_dev != d->stat.st_dev)
                {
                        show_error_dir("Directory changed or unavailable", d, d->name);
                }
                d->fd = fd;
        }
        d->fdrefs++;
        return d->fd;
}

int dir_close_unlocked(Directory *d) {
        d->fdrefs--;
        assert(d->refs>=0);
        if (d->fdrefs==0) {
                assert(d->fd>=0);
                if (close(d->fd)<0) {
                        show_error("Directory close failed?! Exiting now with status 2", dir_path(d));
                        exit(2);
                }
                d->fd=-1;
        }
        return 0;
}

/* Opens a file or directory, hopefully safely  */
int dir_openat_unlocked(Directory *parent, const char *name)
{
        assert(!parent || parent->magick==0xDADDAD);
        int pfd = (parent) ? dir_open_unlocked(parent) : AT_FDCWD;
        int dfd = openat(pfd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NOATIME);
        if (dfd < 0 && errno == EPERM)
                dfd = openat(pfd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW); // Try again without O_NOATIME
        if (dfd < 0) {
                if (errno==EMFILE) {
                        show_error_dir("dir_openat probably a fd leak BUG", parent, name);
                        abort();
                }
                show_error_dir("dir_openat", parent, name);
                abort();
        }
        if (parent && pfd>=0) dir_close_unlocked(parent);
        return dfd;
}

int dir_open(Directory *d)
{
        if (d==NULL) return AT_FDCWD; // hack
        pthread_mutex_lock(&d->mut);
        int fd = dir_open_unlocked(d);
        pthread_mutex_unlock(&d->mut);
        return fd;
}

int dir_close(Directory *d) {
        if (d==NULL) return 0;
        pthread_mutex_lock(&d->mut); 
        dir_close_unlocked(d);
        pthread_mutex_unlock(&d->mut);
        return 0;
}

int dir_openat(Directory *parent, const char *name) {
        if (!parent) return dir_openat_unlocked(NULL, name); // FIXME: directory root does not have a parent o lock. Maybe it should. 
        pthread_mutex_lock(&parent->mut);
        int dfd=dir_openat_unlocked(parent, name);
        pthread_mutex_unlock(&parent->mut);
        return dfd;
}


/* Free a directory structure, including its finished jobs */
void d_freedir_locked(Directory *dir)
{
        assert(dir->magick == 0xDADDAD);
        assert(dir->refs>=0);
        assert(dir->parent_entry && dir->parent_entry->dir==dir);

        dir->refs--;
        if (dir->refs > 0)
        {
                return;
        }
        assert(dir->fdrefs==0);

        scans.dirs_active--;
        scans.entries_active -= dir->entries;
        scans.dirs_freed++;

        while (dir->entries > 0)
        {
                dir->entries--;
                Entry *e = &dir->array[dir->entries];
                assert(!e->job); // no job should be running on this entry
                assert(!e->wait_queue);
                if (e->link)
                        free(e->link);
                free(e->name);
        }
        free(dir->array);
        free(dir->sorted);

        dir->magick = 0xDADDEAD;
        if (dir->fd >= 0)
                close(dir->fd);

        free(dir->name);
        dir->entries = -123; /* Magic value to debug a race */
        dir->parent_entry->dir=NULL;
        if (dir->parent)
                d_freedir_locked(dir->parent);
        free(dir);
}

void d_freedir(Directory *dir)
{
        pthread_mutex_lock(&mut);
        d_freedir_locked(dir);
        pthread_mutex_unlock(&mut);
}       

static int entrycmp(const void *x, const void *y) {
        Entry **a = (Entry **)x;
        Entry **b = (Entry **)y;
        return strcmp((*a)->name, (*b)->name);
}

/* Directory read is split in two Jobs
 * - read_directory reads a directory and submits more directories to be read
 * - Doesn't stat the entries, because stats are slow and we wan't the job size quickly
 */
int read_directory(Directory *parent, Entry *parent_entry, Directory *not_used_d, const char *name, off_t depth)
{
        int allocated = 1024;
        int dfd = -1;
        DIR *d = NULL;
        struct stat tmp_stat;
        int entries = 0;
        int ret=RET_OK; 

        assert(!parent || parent->magick != 0xDADDEAD);
        assert(!parent || parent->magick == 0xDADDAD);

        set_thread_status(file_path(parent,name),"read_directory");

        pthread_mutex_lock(&mut);
        switch (parent_entry->state) {
                case ENTRY_CREATED:  // FIXME dsync() does not init parent_entry. It probably should
                case ENTRY_INIT: break;
                case ENTRY_READ_QUEUE: break;
                case ENTRY_READING: ret=RET_RUNNING; goto out;  /* Some thread is already doing it */
                case ENTRY_READ_READY: 
                case ENTRY_SCAN_QUEUE:
                case ENTRY_SCAN_RUNNING:
                case ENTRY_SCAN_READY: goto out; // Already done 
                case ENTRY_DELETED: goto out;    // Deleted already
        }

        // We won the race and get to read the directory
        Directory *nd=my_calloc(1, sizeof(Directory));
        parent_entry->dir=nd; // will be filled when we finish
        parent_entry->state=ENTRY_READING;
        pthread_mutex_unlock(&mut);

        if ((dfd = dir_openat(parent, name)) < 0 || (d = fdopendir(dfd)) == NULL || fstat(dfd, &tmp_stat) < 0)
        {
                show_error_dir("read_directory", parent, name);
                if (dfd >= 0) close(dfd);
                ret=RET_FAILED;
                goto out;
        }

        /* Read the directory and save the names and dents */
        Dent *dents = my_calloc(allocated, sizeof(*dents));
        errno = 0;
        struct dirent *dent;
        while ((dent = readdir(d)))
        {
                if (dent->d_name[0] == '.')
                {
                        /* Skip '.' and '..' */
                        if (dent->d_name[1] == 0)
                                continue;
                        if (dent->d_name[1] == '.' && dent->d_name[2] == 0)
                                continue;
                }
                if (entries == allocated)
                {
                        allocated += allocated / 2;
                        dents = my_realloc(dents, sizeof(*dents) * allocated);
                }
                dents[entries].name = my_strdup(dent->d_name);
                dents[entries].d_ino = dent->d_ino;
                dents[entries].d_type = dent->d_type;
                entries++;
        }
        if (errno)
        {
                show_error_dir("readdir", parent, name);
                free(dents);
        }

        /* Init the Directory structure */
        nd->parent = parent;
        nd->name = my_strdup(name);
        nd->parent_entry = parent_entry;
        nd->refs = 1; /* The directory is now referenced once */
        memcpy(&nd->stat, &tmp_stat, sizeof(tmp_stat));
        nd->magick = 0xDADDAD;
        nd->fd = -1;
        nd->entries=entries;
        nd->array = my_calloc(entries, sizeof(Entry));
        nd->sorted = my_calloc(entries, sizeof(Entry *));
        pthread_mutex_init(&nd->mut, 0);

        /* Init the entry array for Directories and submit jobs */
        for (int i = 0; recursive && i < entries; i++) {
                nd->array[i].name=dents[i].name;
                if (dents[i].d_type==DT_DIR) {
                        Entry *e=&nd->array[i];
                        init_entry(e, dfd, e->name);
                        e->state=ENTRY_READ_QUEUE;
                        //printf("submit job %s depth %ld\n",file_path(nd, e->name), depth+1);
                        if ( S_ISDIR(e->stat.st_mode) ) {
                                submit_job(nd, e, NULL, e->name, depth+1, read_directory);
                        } else {
                                // FIXME: do we need to handle a case like this?
                                show_error_dir("read_directory inode changed. Exiting.", parent, e->name);
                                exit(1);
                        }
                }
        }
        closedir(d);
        free(dents);

        /* Now create the sorted array */
        for (int i=0; i<entries; i++) nd->sorted[i]=&nd->array[i];
        qsort(nd->sorted, entries, sizeof(Entry *), entrycmp);

        pthread_mutex_lock(&mut);
        while (parent) {
                atomic_fetch_add(&parent->descendants, entries);
                parent=parent->parent;
        }
        parent_entry->state=ENTRY_READ_READY;

        /* Update stats */
        if (++scans.dirs_active > scans.dirs_active_max) scans.dirs_active_max = scans.dirs_active;
        scans.entries_active += entries;
        //printf("readdir done %s %ld\n",file_path(parent,name),depth);

        out: 
        pthread_cond_broadcast(&cond);
        pthread_mutex_unlock(&mut);
        return ret;
}

/* scan_directory can be called from multiple threads */
Directory *scan_directory(Directory *parent, Entry *entry)
{
        assert(!parent || parent->magick != 0xDADDEAD);
        assert(!parent || parent->magick == 0xDADDAD);

        //printf("scan directory %s\n", file_path(parent, entry->name)); 
        while(read_directory(parent, entry, NULL, entry->name, 0)==RET_RUNNING) {
                pthread_mutex_lock(&mut);
                run_any_job();
                pthread_mutex_unlock(&mut);      
        }

        Directory *nd=entry->dir;
        assert(entry->state==ENTRY_READ_READY);
        entry->state=ENTRY_SCAN_RUNNING;;
        assert(nd); // FIXME: can be NULL on directory read failure
        set_thread_status(file_path(parent, entry->name), "scandir");

        if (dir_open(nd) < 0) {
                d_freedir(nd);
                return NULL;
        }

        /* Initialize ((stat) all the entries which have not been stated, in readdir() order */
        for (int i = 0; i < nd->entries; i++) {
                Entry *e = &nd->array[i];
                if (e->state==ENTRY_CREATED) init_entry(e, nd->fd, e->name);
        }

        set_thread_status(file_path(parent, entry->name), "scandir done");
        dir_close(nd);
        return nd;
}


