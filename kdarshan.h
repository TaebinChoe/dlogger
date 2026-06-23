#ifndef __KDARSHAN_H
#define __KDARSHAN_H

#define MAX_PATH_LEN 256

#define X(a) a,
enum darshan_posix_indices
{
    POSIX_OPENS = 0,
    POSIX_FILENOS,
    POSIX_DUPS,
    POSIX_READS,
    POSIX_WRITES,
    POSIX_SEEKS,
    POSIX_STATS,
    POSIX_MMAPS,
    POSIX_FSYNCS,
    POSIX_FDSYNCS,
    POSIX_RENAME_SOURCES,
    POSIX_RENAME_TARGETS,
    POSIX_RENAMED_FROM,
    POSIX_MODE,
    POSIX_BYTES_READ,
    POSIX_BYTES_WRITTEN,
    POSIX_MAX_BYTE_READ,
    POSIX_MAX_BYTE_WRITTEN,
    POSIX_CONSEC_READS,
    POSIX_CONSEC_WRITES,
    POSIX_SEQ_READS,
    POSIX_SEQ_WRITES,
    POSIX_RW_SWITCHES,
    POSIX_MEM_NOT_ALIGNED,
    POSIX_MEM_ALIGNMENT,
    POSIX_FILE_NOT_ALIGNED,
    POSIX_FILE_ALIGNMENT,
    POSIX_MAX_READ_TIME_SIZE,
    POSIX_MAX_WRITE_TIME_SIZE,
    POSIX_SIZE_READ_0_100,
    POSIX_SIZE_READ_100_1K,
    POSIX_SIZE_READ_1K_10K,
    POSIX_SIZE_READ_10K_100K,
    POSIX_SIZE_READ_100K_1M,
    POSIX_SIZE_READ_1M_4M,
    POSIX_SIZE_READ_4M_10M,
    POSIX_SIZE_READ_10M_100M,
    POSIX_SIZE_READ_100M_1G,
    POSIX_SIZE_READ_1G_PLUS,
    POSIX_SIZE_WRITE_0_100,
    POSIX_SIZE_WRITE_100_1K,
    X(POSIX_SIZE_WRITE_1K_10K)
    X(POSIX_SIZE_WRITE_10K_100K)
    X(POSIX_SIZE_WRITE_100K_1M)
    X(POSIX_SIZE_WRITE_1M_4M)
    X(POSIX_SIZE_WRITE_4M_10M)
    X(POSIX_SIZE_WRITE_10M_100M)
    X(POSIX_SIZE_WRITE_100M_1G)
    X(POSIX_SIZE_WRITE_1G_PLUS)
    X(POSIX_STRIDE1_STRIDE)
    X(POSIX_STRIDE2_STRIDE)
    X(POSIX_STRIDE3_STRIDE)
    X(POSIX_STRIDE4_STRIDE)
    X(POSIX_STRIDE1_COUNT)
    X(POSIX_STRIDE2_COUNT)
    X(POSIX_STRIDE3_COUNT)
    X(POSIX_STRIDE4_COUNT)
    X(POSIX_ACCESS1_ACCESS)
    X(POSIX_ACCESS2_ACCESS)
    X(POSIX_ACCESS3_ACCESS)
    X(POSIX_ACCESS4_ACCESS)
    X(POSIX_ACCESS1_COUNT)
    X(POSIX_ACCESS2_COUNT)
    X(POSIX_ACCESS3_COUNT)
    X(POSIX_ACCESS4_COUNT)
    X(POSIX_FASTEST_RANK)
    X(POSIX_FASTEST_RANK_BYTES)
    X(POSIX_SLOWEST_RANK)
    X(POSIX_SLOWEST_RANK_BYTES)
    POSIX_NUM_INDICES
};

enum darshan_posix_f_indices
{
    POSIX_F_OPEN_START_TIMESTAMP = 0,
    POSIX_F_READ_START_TIMESTAMP,
    POSIX_F_WRITE_START_TIMESTAMP,
    POSIX_F_CLOSE_START_TIMESTAMP,
    POSIX_F_OPEN_END_TIMESTAMP,
    POSIX_F_READ_END_TIMESTAMP,
    POSIX_F_WRITE_END_TIMESTAMP,
    POSIX_F_CLOSE_END_TIMESTAMP,
    POSIX_F_READ_TIME,
    POSIX_F_WRITE_TIME,
    POSIX_F_META_TIME,
    POSIX_F_MAX_READ_TIME,
    POSIX_F_MAX_WRITE_TIME,
    POSIX_F_FASTEST_RANK_TIME,
    POSIX_F_SLOWEST_RANK_TIME,
    POSIX_F_VARIANCE_RANK_TIME,
    POSIX_F_VARIANCE_RANK_BYTES,
    POSIX_F_NUM_INDICES
};
#undef X

/* File statistics tracked in BPF map and reported to userspace */
struct kdarshan_file_stats {
    unsigned long long path_hash;
    long long counters[POSIX_NUM_INDICES];
    unsigned long long fcounters[POSIX_F_NUM_INDICES];
};

/* State tracked per active FD in BPF map */
struct fd_state {
    unsigned long long path_hash;
    long long last_byte_read;
    long long last_byte_written;
    unsigned int last_io_type; // 0: None, 1: Read, 2: Write
};

/* Open request arguments mapped temporarily during enter/exit */
struct open_args {
    const char *filename;
    int dfd;
    int flags;
    int mode;
};

/* Read/write context mapped temporarily during enter/exit */
struct rw_args {
    int fd;
    long long offset;
    long long length;
    unsigned long long start_ns;
};

#endif /* __KDARSHAN_H */
