#ifndef __DLOGGER_H
#define __DLOGGER_H

#define MAX_PATH_LEN 256

/* Event sent via ring buffer to assign path name to hash */
struct path_event {
    unsigned long long path_hash;
    unsigned int pid;
    unsigned long long cgroup_id;
    unsigned long long start_time;
    char comm[16];
    char path[MAX_PATH_LEN];
};

/* Event sent via ring buffer for DXT tracing */
struct dxt_event {
    unsigned long long path_hash;
    unsigned long long start_ns;
    unsigned long long end_ns;
    long long offset;
    long long length;
    unsigned int pid;
    unsigned long long cgroup_id;
    unsigned long long start_time;
    unsigned int write_flag; // 0: read, 1: write
};

#endif /* __DLOGGER_H */
