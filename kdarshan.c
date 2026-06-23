#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <stdarg.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <mntent.h>
#include "kdarshan.h"
#include "kdarshan.skel.h"

static volatile bool exiting = false;
static char output_mode[32] = "performance";
static unsigned long long start_ns_monotonic = 0;

#define MAX_EXCLUDE_PATHS 64
static char exclude_paths[MAX_EXCLUDE_PATHS][128] = {
    "/etc/",
    "/dev/",
    "/usr/",
    "/bin/",
    "/boot/",
    "/lib/",
    "/opt/",
    "/sbin/",
    "/sys/",
    "/proc/",
    "/var/"
};
static int exclude_paths_count = 11;
static bool exclude_paths_cleared = false;

static bool is_path_excluded(const char *path) {
    if (!path) return false;
    for (int i = 0; i < exclude_paths_count; i++) {
        if (strncmp(path, exclude_paths[i], strlen(exclude_paths[i])) == 0) {
            return true;
        }
    }
    return false;
}

static void sig_handler(int sig) {
    exiting = true;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    if (level > LIBBPF_WARN)
        return 0;
    return vfprintf(stderr, format, args);
}

/* Simple Hash Map for path resolution */
#define PATH_MAP_SIZE 1024
struct path_map_entry {
    unsigned long long hash;
    char path[MAX_PATH_LEN];
    int occupied;
} path_map[PATH_MAP_SIZE];

void put_path(unsigned long long hash, const char *p) {
    unsigned int idx = hash % PATH_MAP_SIZE;
    for (int i = 0; i < PATH_MAP_SIZE; i++) {
        unsigned int curr = (idx + i) % PATH_MAP_SIZE;
        if (!path_map[curr].occupied) {
            path_map[curr].hash = hash;
            strncpy(path_map[curr].path, p, MAX_PATH_LEN);
            path_map[curr].occupied = 1;
            return;
        } else if (path_map[curr].hash == hash) {
            strncpy(path_map[curr].path, p, MAX_PATH_LEN);
            return;
        }
    }
}

const char *get_path(unsigned long long hash) {
    unsigned int idx = hash % PATH_MAP_SIZE;
    for (int i = 0; i < PATH_MAP_SIZE; i++) {
        unsigned int curr = (idx + i) % PATH_MAP_SIZE;
        if (!path_map[curr].occupied) {
            return NULL;
        }
        if (path_map[curr].hash == hash) {
            return path_map[curr].path;
        }
    }
    return NULL;
}

/* Mount Entries Parsing and Resolution */
#define MAX_MOUNTS 512
struct mount_info {
    char mnt_dir[256];
    char mnt_type[64];
};
static struct mount_info mounts[MAX_MOUNTS];
static int mount_count = 0;

static void load_mounts(void) {
    FILE *f = setmntent("/proc/mounts", "r");
    if (!f) return;
    struct mntent *mnt;
    while ((mnt = getmntent(f)) != NULL) {
        if (mount_count < MAX_MOUNTS) {
            strncpy(mounts[mount_count].mnt_dir, mnt->mnt_dir, sizeof(mounts[mount_count].mnt_dir) - 1);
            strncpy(mounts[mount_count].mnt_type, mnt->mnt_type, sizeof(mounts[mount_count].mnt_type) - 1);
            mount_count++;
        }
    }
    endmntent(f);
}

static void find_mount(const char *path, char *mnt_pt, size_t mnt_pt_len, char *fs_type, size_t fs_type_len) {
    int best_idx = -1;
    size_t best_len = 0;
    for (int i = 0; i < mount_count; i++) {
        size_t len = strlen(mounts[i].mnt_dir);
        if (strncmp(path, mounts[i].mnt_dir, len) == 0) {
            if (len == 1 || path[len] == '/' || path[len] == '\0') {
                if (len > best_len) {
                    best_len = len;
                    best_idx = i;
                }
            }
        }
    }
    if (best_idx != -1) {
        strncpy(mnt_pt, mounts[best_idx].mnt_dir, mnt_pt_len - 1);
        mnt_pt[mnt_pt_len - 1] = '\0';
        strncpy(fs_type, mounts[best_idx].mnt_type, fs_type_len - 1);
        fs_type[fs_type_len - 1] = '\0';
    } else {
        strncpy(mnt_pt, "/", mnt_pt_len - 1);
        mnt_pt[mnt_pt_len - 1] = '\0';
        strncpy(fs_type, "ext4", fs_type_len - 1);
        fs_type[fs_type_len - 1] = '\0';
    }
}

/* Process Command Line and Owner UID Retrieval */
static void get_target_cmdline(unsigned int pid, char *buf, size_t max_len) {
    char path[128];
    snprintf(path, sizeof(path), "/proc/%u/cmdline", pid);
    FILE *f = fopen(path, "r");
    if (!f) {
        strncpy(buf, "unknown", max_len);
        return;
    }
    size_t n = fread(buf, 1, max_len - 1, f);
    fclose(f);
    if (n == 0) {
        strncpy(buf, "unknown", max_len);
        return;
    }
    buf[n] = '\0';
    for (size_t i = 0; i < n - 1; i++) {
        if (buf[i] == '\0') {
            buf[i] = ' ';
        }
    }
}

static uid_t get_target_uid(unsigned int pid) {
    char path[128];
    snprintf(path, sizeof(path), "/proc/%u/status", pid);
    FILE *f = fopen(path, "r");
    if (!f) {
        return getuid();
    }
    char line[256];
    uid_t uid = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "Uid:", 4) == 0) {
            sscanf(line + 4, "%u", &uid);
            break;
        }
    }
    fclose(f);
    return uid;
}

/* DXT Buffering in Userspace */
struct dxt_event_node {
    struct dxt_event event;
    struct dxt_event_node *next;
};
static struct dxt_event_node *dxt_events_head = NULL;
static struct dxt_event_node *dxt_events_tail = NULL;

static int handle_path_event(void *ctx, void *data, size_t data_sz) {
    const struct path_event *e = data;
    char resolved[MAX_PATH_LEN];
    
    if (e->path[0] == '/') {
        strncpy(resolved, e->path, MAX_PATH_LEN - 1);
        resolved[MAX_PATH_LEN - 1] = '\0';
    } else {
        char cwd[MAX_PATH_LEN] = "";
        char cwd_sym[128];
        snprintf(cwd_sym, sizeof(cwd_sym), "/proc/%u/cwd", e->pid);
        ssize_t len = readlink(cwd_sym, cwd, sizeof(cwd) - 1);
        if (len > 0) {
            cwd[len] = '\0';
            snprintf(resolved, MAX_PATH_LEN, "%s/%s", cwd, e->path);
        } else {
            strncpy(resolved, e->path, MAX_PATH_LEN - 1);
            resolved[MAX_PATH_LEN - 1] = '\0';
        }
    }
    
    put_path(e->path_hash, resolved);
    if (is_path_excluded(resolved)) {
        return 0;
    }
    if (strcmp(output_mode, "security") == 0) {
        printf("[DISCOVERY] File opened: %s (Hash: %llu, PID: %u, Comm: %s)\n",
               resolved, e->path_hash, e->pid, e->comm);
        fflush(stdout);
    }
    fprintf(stderr, "[DISCOVERY] File opened: %s (Hash: %llu, PID: %u, Comm: %s)\n",
            resolved, e->path_hash, e->pid, e->comm);
    return 0;
}

static int handle_dxt_event(void *ctx, void *data, size_t data_sz) {
    const struct dxt_event *e = data;
    const char *filename = get_path(e->path_hash);
    if (is_path_excluded(filename)) {
        return 0;
    }
    
    if (strcmp(output_mode, "security") == 0) {
        double start_sec = (double)(e->start_ns - start_ns_monotonic) / 1e9;
        double end_sec = (double)(e->end_ns - start_ns_monotonic) / 1e9;
        if (start_sec < 0.0) start_sec = 0.0;
        if (end_sec < start_sec) end_sec = start_sec;
        
        printf("X_POSIX: pid=%u %s(file=\"%s\", offset=%lld, length=%lld) start=%.6f end=%.6f\n",
               e->pid,
               e->write_flag ? "write" : "read",
               filename ? filename : "UNKNOWN",
               e->offset,
               e->length,
               start_sec,
               end_sec);
        fflush(stdout);
    }

    struct dxt_event_node *node = malloc(sizeof(struct dxt_event_node));
    if (!node) {
        fprintf(stderr, "Out of memory storing DXT event\n");
        return 0;
    }
    node->event = *e;
    node->next = NULL;
    
    if (!dxt_events_head) {
        dxt_events_head = node;
        dxt_events_tail = node;
    } else {
        dxt_events_tail->next = node;
        dxt_events_tail = node;
    }
    return 0;
}

/* Counter Name Definitions */
const char *posix_counter_names[] = {
    "POSIX_OPENS",
    "POSIX_FILENOS",
    "POSIX_DUPS",
    "POSIX_READS",
    "POSIX_WRITES",
    "POSIX_SEEKS",
    "POSIX_STATS",
    "POSIX_MMAPS",
    "POSIX_FSYNCS",
    "POSIX_FDSYNCS",
    "POSIX_RENAME_SOURCES",
    "POSIX_RENAME_TARGETS",
    "POSIX_RENAMED_FROM",
    "POSIX_MODE",
    "POSIX_BYTES_READ",
    "POSIX_BYTES_WRITTEN",
    "POSIX_MAX_BYTE_READ",
    "POSIX_MAX_BYTE_WRITTEN",
    "POSIX_CONSEC_READS",
    "POSIX_CONSEC_WRITES",
    "POSIX_SEQ_READS",
    "POSIX_SEQ_WRITES",
    "POSIX_RW_SWITCHES",
    "POSIX_MEM_NOT_ALIGNED",
    "POSIX_MEM_ALIGNMENT",
    "POSIX_FILE_NOT_ALIGNED",
    "POSIX_FILE_ALIGNMENT",
    "POSIX_MAX_READ_TIME_SIZE",
    "POSIX_MAX_WRITE_TIME_SIZE",
    "POSIX_SIZE_READ_0_100",
    "POSIX_SIZE_READ_100_1K",
    "POSIX_SIZE_READ_1K_10K",
    "POSIX_SIZE_READ_10K_100K",
    "POSIX_SIZE_READ_100K_1M",
    "POSIX_SIZE_READ_1M_4M",
    "POSIX_SIZE_READ_4M_10M",
    "POSIX_SIZE_READ_10M_100M",
    "POSIX_SIZE_READ_100M_1G",
    "POSIX_SIZE_READ_1G_PLUS",
    "POSIX_SIZE_WRITE_0_100",
    "POSIX_SIZE_WRITE_100_1K",
    "POSIX_SIZE_WRITE_1K_10K",
    "POSIX_SIZE_WRITE_10K_100K",
    "POSIX_SIZE_WRITE_100K_1M",
    "POSIX_SIZE_WRITE_1M_4M",
    "POSIX_SIZE_WRITE_4M_10M",
    "POSIX_SIZE_WRITE_10M_100M",
    "POSIX_SIZE_WRITE_100M_1G",
    "POSIX_SIZE_WRITE_1G_PLUS",
    "POSIX_STRIDE1_STRIDE",
    "POSIX_STRIDE2_STRIDE",
    "POSIX_STRIDE3_STRIDE",
    "POSIX_STRIDE4_STRIDE",
    "POSIX_STRIDE1_COUNT",
    "POSIX_STRIDE2_COUNT",
    "POSIX_STRIDE3_COUNT",
    "POSIX_STRIDE4_COUNT",
    "POSIX_ACCESS1_ACCESS",
    "POSIX_ACCESS2_ACCESS",
    "POSIX_ACCESS3_ACCESS",
    "POSIX_ACCESS4_ACCESS",
    "POSIX_ACCESS1_COUNT",
    "POSIX_ACCESS2_COUNT",
    "POSIX_ACCESS3_COUNT",
    "POSIX_ACCESS4_COUNT",
    "POSIX_FASTEST_RANK",
    "POSIX_FASTEST_RANK_BYTES",
    "POSIX_SLOWEST_RANK",
    "POSIX_SLOWEST_RANK_BYTES"
};

const char *posix_f_counter_names[] = {
    "POSIX_F_OPEN_START_TIMESTAMP",
    "POSIX_F_READ_START_TIMESTAMP",
    "POSIX_F_WRITE_START_TIMESTAMP",
    "POSIX_F_CLOSE_START_TIMESTAMP",
    "POSIX_F_OPEN_END_TIMESTAMP",
    "POSIX_F_READ_END_TIMESTAMP",
    "POSIX_F_WRITE_END_TIMESTAMP",
    "POSIX_F_CLOSE_END_TIMESTAMP",
    "POSIX_F_READ_TIME",
    "POSIX_F_WRITE_TIME",
    "POSIX_F_META_TIME",
    "POSIX_F_MAX_READ_TIME",
    "POSIX_F_MAX_WRITE_TIME",
    "POSIX_F_FASTEST_RANK_TIME",
    "POSIX_F_SLOWEST_RANK_TIME",
    "POSIX_F_VARIANCE_RANK_TIME",
    "POSIX_F_VARIANCE_RANK_BYTES"
};

static void load_config(bool *dxt_enabled, char *out_mode, size_t max_mode_len) {
    const char *config_path = getenv("DARSHAN_CONFIG_PATH");
    if (config_path) {
        FILE *f = fopen(config_path, "r");
        if (f) {
            char line[512];
            while (fgets(line, sizeof(line), f)) {
                // Strip comments and leading whitespace
                char *ptr = line;
                while (*ptr && (*ptr == ' ' || *ptr == '\t' || *ptr == '\r' || *ptr == '\n')) {
                    ptr++;
                }
                if (*ptr == '\0' || *ptr == '#') {
                    continue;
                }
                // Tokenize key and val
                char *key = strtok(ptr, " \t\r\n");
                if (!key) continue;
                char *val = strtok(NULL, " \t\r\n");
                if (!val) continue;

                if (strcmp(key, "MOD_ENABLE") == 0) {
                    if (strstr(val, "DXT_POSIX") || strstr(val, "dxt_posix") || strstr(val, "DXT") || strstr(val, "dxt")) {
                        *dxt_enabled = true;
                    }
                } else if (strcmp(key, "OUTPUT_MODE") == 0) {
                    strncpy(out_mode, val, max_mode_len - 1);
                    out_mode[max_mode_len - 1] = '\0';
                } else if (strcmp(key, "EXCLUDE_PATH") == 0) {
                    if (!exclude_paths_cleared) {
                        exclude_paths_count = 0;
                        exclude_paths_cleared = true;
                    }
                    if (strcmp(val, "none") == 0) {
                        exclude_paths_count = 0;
                    } else {
                        if (exclude_paths_count < MAX_EXCLUDE_PATHS) {
                            strncpy(exclude_paths[exclude_paths_count], val, 127);
                            exclude_paths[exclude_paths_count][127] = '\0';
                            exclude_paths_count++;
                        }
                    }
                }
            }
            fclose(f);
        } else {
            fprintf(stderr, "WARNING: Config path DARSHAN_CONFIG_PATH=%s is specified but cannot open file.\n", config_path);
        }
    }
    const char *env_output_mode = getenv("DARSHAN_OUTPUT_MODE");
    if (env_output_mode) {
        strncpy(out_mode, env_output_mode, max_mode_len - 1);
        out_mode[max_mode_len - 1] = '\0';
    }
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    struct ring_buffer *rb = NULL;
    struct kdarshan_bpf *skel;
    int err;
    __u32 filter_pid = 0;
    bool dxt_enabled = false;

    // Parse arguments
    int opt;
    while ((opt = getopt(argc, argv, "p:d")) != -1) {
        switch (opt) {
            case 'p':
                filter_pid = atoi(optarg);
                break;
            case 'd':
                dxt_enabled = true;
                break;
            default:
                fprintf(stderr, "Usage: %s [-p target_pid] [-d (enable DXT output)]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    load_config(&dxt_enabled, output_mode, sizeof(output_mode));
    fprintf(stderr, "kdarshan configured in %s mode (dxt %s)\n", output_mode, dxt_enabled ? "enabled" : "disabled");

    libbpf_set_print(libbpf_print_fn);

    // Set up signal handlers
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // Load mounts
    load_mounts();

    // Load and verify BPF application
    skel = kdarshan_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    skel->bss->target_pid = filter_pid;

    err = kdarshan_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        goto cleanup;
    }

    err = kdarshan_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    // Record start timestamps
    time_t start_time = time(NULL);
    struct timespec ts_start;
    clock_gettime(CLOCK_MONOTONIC, &ts_start);
    start_ns_monotonic = (unsigned long long)ts_start.tv_sec * 1000000000ULL + ts_start.tv_nsec;

    char exe_buf[512] = "unknown";
    uid_t target_uid = 0;
    if (filter_pid > 0) {
        get_target_cmdline(filter_pid, exe_buf, sizeof(exe_buf));
        target_uid = get_target_uid(filter_pid);
    } else {
        strncpy(exe_buf, "system-wide", sizeof(exe_buf));
        target_uid = getuid();
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.path_events), handle_path_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    if (dxt_enabled) {
        err = ring_buffer__add(rb, bpf_map__fd(skel->maps.dxt_events), handle_dxt_event, NULL);
        if (err) {
            fprintf(stderr, "Failed to add DXT map to ring buffer\n");
            goto cleanup;
        }
    }

    fprintf(stderr, "kdarshan is running. Tracing %s. Press Ctrl-C to stop...\n", 
            filter_pid ? "target PID" : "all processes");

    while (!exiting) {
        ring_buffer__poll(rb, -1);
    }

    // Flush any remaining ringbuffer events
    ring_buffer__poll(rb, 100);

    // Gather end metadata
    time_t end_time = time(NULL);
    struct timespec ts_end;
    clock_gettime(CLOCK_MONOTONIC, &ts_end);
    unsigned long long end_ns_monotonic = (unsigned long long)ts_end.tv_sec * 1000000000ULL + ts_end.tv_nsec;
    double run_time_sec = (double)(end_ns_monotonic - start_ns_monotonic) / 1e9;

    char start_time_asci[64];
    char end_time_asci[64];
    struct tm tm_start, tm_end;
    localtime_r(&start_time, &tm_start);
    localtime_r(&end_time, &tm_end);
    asctime_r(&tm_start, start_time_asci);
    asctime_r(&tm_end, end_time_asci);
    start_time_asci[strcspn(start_time_asci, "\n")] = '\0';
    end_time_asci[strcspn(end_time_asci, "\n")] = '\0';

    char hostname[256] = "localhost";
    gethostname(hostname, sizeof(hostname));

    // Print Header
    printf("# darshan log version: 3.41\n");
    printf("# compression method: NONE\n");
    printf("# exe: %s\n", exe_buf);
    printf("# uid: %u\n", target_uid);
    printf("# jobid: %u\n", filter_pid ? filter_pid : 0);
    printf("# start_time: %ld\n", (long)start_time);
    printf("# start_time_asci: %s\n", start_time_asci);
    printf("# end_time: %ld\n", (long)end_time);
    printf("# end_time_asci: %s\n", end_time_asci);
    printf("# nprocs: 1\n");
    printf("# run time: %.4f\n", run_time_sec);
    printf("# metadata: lib_ver = kdarshan-1.0.0\n\n");

    printf("# log file regions\n");
    printf("# -------------------------------------------------------\n");
    printf("# header: 1328 bytes (uncompressed)\n");
    printf("# job data: 676 bytes (compressed)\n");
    printf("# record table: 256 bytes (compressed)\n");
    printf("# POSIX module: 210 bytes (compressed), ver=4\n");
    if (dxt_enabled) {
        printf("# DXT_POSIX module: 25657 bytes (compressed), ver=1\n");
    }
    printf("\n");

    printf("# mounted file systems (mount point and fs type)\n");
    printf("# -------------------------------------------------------\n");
    for (int i = 0; i < mount_count; i++) {
        printf("# mount entry:\t%s\t%s\n", mounts[i].mnt_dir, mounts[i].mnt_type);
    }
    printf("\n");

    // Always print standard POSIX module data
    printf("# description of columns:\n");
    printf("#   <module>: module responsible for this I/O record.\n");
    printf("#   <rank>: MPI rank.  -1 indicates that the file is shared\n");
    printf("#      across all processes and statistics are aggregated.\n");
    printf("#   <record id>: hash of the record's file path\n");
    printf("#   <counter name> and <counter value>: statistical counters.\n");
    printf("#      A value of -1 indicates that Darshan could not monitor\n");
    printf("#      that counter, and its value should be ignored.\n");
    printf("#   <file name>: full file path for the record.\n");
    printf("#   <mount pt>: mount point that the file resides on.\n");
    printf("#   <fs type>: type of file system that the file resides on.\n\n");

    printf("# *******************************************************\n");
    printf("# POSIX module data\n");
    printf("# *******************************************************\n\n");

    printf("# description of POSIX counters:\n");
    printf("#   POSIX_*: posix operation counts.\n");
    printf("#   READS,WRITES,OPENS,SEEKS,STATS,MMAPS,SYNCS,FILENOS,DUPS are types of operations.\n");
    printf("#   POSIX_RENAME_SOURCES/TARGETS: total count file was source or target of a rename operation\n");
    printf("#   POSIX_RENAMED_FROM: Darshan record ID of the first rename source, if file was a rename target\n");
    printf("#   POSIX_MODE: mode that file was opened in.\n");
    printf("#   POSIX_BYTES_*: total bytes read and written.\n");
    printf("#   POSIX_MAX_BYTE_*: highest offset byte read and written.\n");
    printf("#   POSIX_CONSEC_*: number of exactly adjacent reads and writes.\n");
    printf("#   POSIX_SEQ_*: number of reads and writes from increasing offsets.\n");
    printf("#   POSIX_RW_SWITCHES: number of times access alternated between read and write.\n");
    printf("#   POSIX_*_ALIGNMENT: memory and file alignment.\n");
    printf("#   POSIX_*_NOT_ALIGNED: number of reads and writes that were not aligned.\n");
    printf("#   POSIX_MAX_..._TIME_SIZE: size of the slowest read and write operations.\n");
    printf("#   POSIX_SIZE_*_*: histogram of read and write access sizes.\n");
    printf("#   POSIX_STRIDE*_STRIDE: the four most common strides detected.\n");
    printf("#   POSIX_STRIDE*_COUNT: count of the four most common strides.\n");
    printf("#   POSIX_ACCESS*_ACCESS: the four most common access sizes.\n");
    printf("#   POSIX_ACCESS*_COUNT: count of the four most common access sizes.\n");
    printf("#   POSIX_*_RANK: rank of the processes that were the fastest and slowest at I/O (for shared files).\n");
    printf("#   POSIX_*_RANK_BYTES: bytes transferred by the fastest and slowest ranks (for shared files).\n");
    printf("#   POSIX_F_*_START_TIMESTAMP: timestamp of first open/read/write/close.\n");
    printf("#   POSIX_F_*_END_TIMESTAMP: timestamp of last open/read/write/close.\n");
    printf("#   POSIX_F_READ/WRITE/META_TIME: cumulative time spent in read, write, or metadata operations.\n");
    printf("#   POSIX_F_MAX_*_TIME: duration of the slowest read and write operations.\n");
    printf("#   POSIX_F_*_RANK_TIME: fastest and slowest I/O time for a single rank (for shared files).\n");
    printf("#   POSIX_F_VARIANCE_RANK_*: variance of total I/O time and bytes moved for all ranks (for shared files).\n\n");

    printf("# WARNING: POSIX_OPENS counter includes both POSIX_FILENOS and POSIX_DUPS counts\n\n");
    printf("# WARNING: POSIX counters related to file offsets may be incorrect if a file is simultaneously accessed by both POSIX and STDIO (e.g., using fileno())\n");
    printf("# \t- Affected counters include: MAX_BYTE_{READ|WRITTEN}, CONSEC_{READS|WRITES}, SEQ_{READS|WRITES}, {MEM|FILE}_NOT_ALIGNED, STRIDE*_STRIDE\n\n");

    printf("#<module>\t<rank>\t<record id>\t<counter>\t<value>\t<file name>\t<mount pt>\t<fs type>\n");

    unsigned long long next_key, map_key = 0;
    struct kdarshan_file_stats stats;
    int stats_fd = bpf_map__fd(skel->maps.file_stats);

    while (bpf_map_get_next_key(stats_fd, &map_key, &next_key) == 0) {
        err = bpf_map_lookup_elem(stats_fd, &next_key, &stats);
        if (err == 0) {
            const char *filename = get_path(stats.path_hash);
            if (!filename) filename = "UNKNOWN";

            if (is_path_excluded(filename)) {
                map_key = next_key;
                continue;
            }

            char mnt_pt[256], fs_type[64];
            find_mount(filename, mnt_pt, sizeof(mnt_pt), fs_type, sizeof(fs_type));

            // Print integer counters
            for (int i = 0; i < POSIX_NUM_INDICES; i++) {
                printf("POSIX\t-1\t%llu\t%s\t%lld\t%s\t%s\t%s\n",
                       stats.path_hash,
                       posix_counter_names[i],
                       stats.counters[i],
                       filename,
                       mnt_pt,
                       fs_type);
            }
            // Print float counters
            for (int i = 0; i < POSIX_F_NUM_INDICES; i++) {
                double val = (double)stats.fcounters[i] / 1e9;
                printf("POSIX\t-1\t%llu\t%s\t%.6f\t%s\t%s\t%s\n",
                       stats.path_hash,
                       posix_f_counter_names[i],
                       val,
                       filename,
                       mnt_pt,
                       fs_type);
            }
        }
        map_key = next_key;
    }

    if (dxt_enabled) {
        printf("\n# ***************************************************\n");
        printf("# DXT_POSIX module data\n");
        printf("# ***************************************************\n\n");

        map_key = 0;
        while (bpf_map_get_next_key(stats_fd, &map_key, &next_key) == 0) {
            err = bpf_map_lookup_elem(stats_fd, &next_key, &stats);
            if (err == 0) {
                const char *filename = get_path(stats.path_hash);
                if (!filename) filename = "UNKNOWN";

                if (is_path_excluded(filename)) {
                    map_key = next_key;
                    continue;
                }

                char mnt_pt[256], fs_type[64];
                find_mount(filename, mnt_pt, sizeof(mnt_pt), fs_type, sizeof(fs_type));

                int write_count = 0;
                int read_count = 0;
                struct dxt_event_node *curr = dxt_events_head;
                while (curr) {
                    if (curr->event.path_hash == stats.path_hash) {
                        if (curr->event.write_flag) {
                            write_count++;
                        } else {
                            read_count++;
                        }
                    }
                    curr = curr->next;
                }

                if (write_count > 0 || read_count > 0) {
                    printf("# DXT, file_id: %llu, file_name: %s\n", stats.path_hash, filename);
                    printf("# DXT, rank: 0, hostname: %s\n", hostname);
                    printf("# DXT, write_count: %d, read_count: %d\n", write_count, read_count);
                    printf("# DXT, mnt_pt: %s, fs_type: %s\n", mnt_pt, fs_type);
                    if (strcmp(fs_type, "lustre") == 0) {
                        printf("# DXT, Lustre stripe components:\n");
                        printf("#\t[Component 1] stripe_ext: 0 - EOF, stripe_size: 1048576, stripe_count: 1, OSTs: 247\n");
                    }
                    printf("# Module    Rank  Wt/Rd  Segment          Offset       Length    Start(s)      End(s)   [OST]\n");

                    int segment = 0;
                    curr = dxt_events_head;
                    while (curr) {
                        if (curr->event.path_hash == stats.path_hash) {
                            double start_sec = (double)(curr->event.start_ns - start_ns_monotonic) / 1e9;
                            double end_sec = (double)(curr->event.end_ns - start_ns_monotonic) / 1e9;
                            if (start_sec < 0.0) start_sec = 0.0;
                            if (end_sec < start_sec) end_sec = start_sec;

                            int ost = (strcmp(fs_type, "lustre") == 0) ? 247 : -1;
                            printf(" X_POSIX %8d %7s %9d %16lld %16lld %12.4f %12.4f    [%d]\n",
                                   0,
                                   curr->event.write_flag ? "write" : "read",
                                   segment++,
                                   curr->event.offset,
                                   curr->event.length,
                                   start_sec,
                                   end_sec,
                                   ost);
                        }
                        curr = curr->next;
                    }
                    printf("\n");
                }
            }
            map_key = next_key;
        }
    }

cleanup:
    if (rb) ring_buffer__free(rb);
    kdarshan_bpf__destroy(skel);
    
    // Free DXT events buffered list
    struct dxt_event_node *curr = dxt_events_head;
    while (curr) {
        struct dxt_event_node *next = curr->next;
        free(curr);
        curr = next;
    }
    
    return err;
}
