#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "kdarshan.h"

#ifndef AT_FDCWD
#define AT_FDCWD -100
#endif
#ifndef O_CREAT
#define O_CREAT 00000100
#endif
#ifndef O_WRONLY
#define O_WRONLY 00000001
#endif
#ifndef O_TRUNC
#define O_TRUNC 00001000
#endif
#ifndef O_APPEND
#define O_APPEND 00002000
#endif
#ifndef O_RDWR
#define O_RDWR 00000002
#endif
#ifndef F_DUPFD
#define F_DUPFD 0
#endif
#ifndef F_DUPFD_CLOEXEC
#define F_DUPFD_CLOEXEC 1030
#endif

char LICENSE[] SEC("license") = "GPL";

/* Maps */
volatile unsigned int target_pid = 0;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, unsigned long long); // path_hash
    __type(value, struct kdarshan_file_stats);
} file_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, unsigned long long); // (tgid << 32) | fd
    __type(value, struct fd_state);
} fd_states SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, unsigned int); // thread_id
    __type(value, struct open_args);
} pending_opens SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, unsigned int); // thread_id
    __type(value, struct rw_args);
} pending_rws SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, unsigned int); // thread_id
    __type(value, int); // fd
} pending_closes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, unsigned int); // thread_id
    __type(value, int); // fd
} pending_seeks SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, unsigned int); // thread_id
    __type(value, int); // fd
} pending_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, unsigned int); // thread_id
    __type(value, int); // oldfd
} pending_dups SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, unsigned int); // thread_id
    __type(value, struct { int fd; int cmd; });
} pending_fcnl SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 262144); // 256KB ringbuf
} path_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1048576); // 1MB ringbuf for DXT
} dxt_events SEC(".maps");

/* Helper function to check if process should be traced */
static __always_inline bool should_trace() {
    unsigned long long pid_tgid = bpf_get_current_pid_tgid();
    unsigned int pid = pid_tgid >> 32;
    
    if (target_pid != 0) {
        return pid == target_pid;
    }
    // Do not trace swapper (pid 0)
    return pid != 0;
}

struct kdarshan_file_stats global_zero_stats;

/* Helper to get or create stats entry */
static __always_inline struct kdarshan_file_stats *get_or_create_stats(unsigned long long path_hash) {
    struct kdarshan_file_stats *stats = bpf_map_lookup_elem(&file_stats, &path_hash);
    if (!stats) {
        bpf_map_update_elem(&file_stats, &path_hash, &global_zero_stats, BPF_NOEXIST);
        stats = bpf_map_lookup_elem(&file_stats, &path_hash);
        if (stats) {
            stats->path_hash = path_hash;
            stats->counters[POSIX_MEM_ALIGNMENT] = 8; // Default memory alignment
            stats->counters[POSIX_FILE_ALIGNMENT] = 4096; // Default file block alignment
        }
    }
    return stats;
}

/* Helper to get the current file position */
static __always_inline long long get_file_pos(int fd) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct files_struct *files = BPF_CORE_READ(task, files);
    if (!files) return 0;
    struct fdtable *fdt = BPF_CORE_READ(files, fdt);
    if (!fdt) return 0;
    struct file *file = NULL;
    struct file **fd_array = BPF_CORE_READ(fdt, fd);
    if (!fd_array) return 0;
    bpf_probe_read_kernel(&file, sizeof(file), &fd_array[fd]);
    if (!file) return 0;
    return BPF_CORE_READ(file, f_pos);
}

/* open / openat / creat */
SEC("tracepoint/syscalls/sys_enter_open")
int tracepoint__syscalls__sys_enter_open(struct trace_event_raw_sys_enter *ctx) {
    if (!should_trace()) return 0;
    unsigned int tid = (unsigned int)bpf_get_current_pid_tgid();
    struct open_args args = {};
    args.filename = (const char *)ctx->args[0];
    args.dfd = AT_FDCWD;
    args.flags = (int)ctx->args[1];
    args.mode = (int)ctx->args[2];
    bpf_map_update_elem(&pending_opens, &tid, &args, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter *ctx) {
    if (!should_trace()) return 0;
    unsigned int tid = (unsigned int)bpf_get_current_pid_tgid();
    struct open_args args = {};
    args.dfd = (int)ctx->args[0];
    args.filename = (const char *)ctx->args[1];
    args.flags = (int)ctx->args[2];
    args.mode = (int)ctx->args[3];
    bpf_map_update_elem(&pending_opens, &tid, &args, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_creat")
int tracepoint__syscalls__sys_enter_creat(struct trace_event_raw_sys_enter *ctx) {
    if (!should_trace()) return 0;
    unsigned int tid = (unsigned int)bpf_get_current_pid_tgid();
    struct open_args args = {};
    args.filename = (const char *)ctx->args[0];
    args.dfd = AT_FDCWD;
    args.flags = O_CREAT | O_WRONLY | O_TRUNC;
    args.mode = (int)ctx->args[1];
    bpf_map_update_elem(&pending_opens, &tid, &args, BPF_ANY);
    return 0;
}

static __always_inline void handle_open_exit(struct trace_event_raw_sys_exit *ctx) {
    unsigned int tid = (unsigned int)bpf_get_current_pid_tgid();
    struct open_args *args = bpf_map_lookup_elem(&pending_opens, &tid);
    if (!args) return;

    long fd = ctx->ret;
    if (fd >= 0) {
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        struct files_struct *files = BPF_CORE_READ(task, files);
        if (files) {
            struct fdtable *fdt = BPF_CORE_READ(files, fdt);
            if (fdt) {
                struct file *file = NULL;
                struct file **fd_array = BPF_CORE_READ(fdt, fd);
                if (fd_array) {
                    bpf_probe_read_kernel(&file, sizeof(file), &fd_array[fd]);
                    if (file) {
                        struct inode *inode = BPF_CORE_READ(file, f_inode);
                        if (inode) {
                            unsigned long ino = BPF_CORE_READ(inode, i_ino);
                            struct super_block *sb = BPF_CORE_READ(inode, i_sb);
                            unsigned int dev = sb ? BPF_CORE_READ(sb, s_dev) : 0;
                            unsigned long block_size = sb ? BPF_CORE_READ(sb, s_blocksize) : 4096;

                            unsigned long long path_hash = ((unsigned long long)dev << 32) | ino;

                            // Send path event to userspace
                            struct path_event *ev = bpf_ringbuf_reserve(&path_events, sizeof(struct path_event), 0);
                            if (ev) {
                                ev->path_hash = path_hash;
                                ev->pid = bpf_get_current_pid_tgid() >> 32;
                                bpf_get_current_comm(&ev->comm, sizeof(ev->comm));
                                long len = bpf_probe_read_user_str(ev->path, sizeof(ev->path), args->filename);
                                if (len < 0) {
                                    ev->path[0] = '\0';
                                }
                                bpf_ringbuf_submit(ev, 0);
                            }

                            // Update stats
                            struct kdarshan_file_stats *stats = get_or_create_stats(path_hash);
                            if (stats) {
                                stats->counters[POSIX_OPENS] += 1;
                                stats->counters[POSIX_MODE] = args->mode;
                                stats->counters[POSIX_FILE_ALIGNMENT] = block_size;
                                
                                unsigned long long now = bpf_ktime_get_ns();
                                if (stats->fcounters[POSIX_F_OPEN_START_TIMESTAMP] == 0) {
                                    stats->fcounters[POSIX_F_OPEN_START_TIMESTAMP] = now;
                                }
                                stats->fcounters[POSIX_F_OPEN_END_TIMESTAMP] = now;
                            }

                            // Update fd state
                            struct fd_state fstate = {};
                            fstate.path_hash = path_hash;
                            fstate.last_byte_read = 0;
                            fstate.last_byte_written = 0;
                            fstate.last_io_type = 0;
                            
                            unsigned long long key = ((unsigned long long)(bpf_get_current_pid_tgid() >> 32) << 32) | fd;
                            bpf_map_update_elem(&fd_states, &key, &fstate, BPF_ANY);
                        }
                    }
                }
            }
        }
    }
    bpf_map_delete_elem(&pending_opens, &tid);
}

SEC("tracepoint/syscalls/sys_exit_open")
int tracepoint__syscalls__sys_exit_open(struct trace_event_raw_sys_exit *ctx) {
    if (!should_trace()) return 0;
    handle_open_exit(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int tracepoint__syscalls__sys_exit_openat(struct trace_event_raw_sys_exit *ctx) {
    if (!should_trace()) return 0;
    handle_open_exit(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_creat")
int tracepoint__syscalls__sys_exit_creat(struct trace_event_raw_sys_exit *ctx) {
    if (!should_trace()) return 0;
    handle_open_exit(ctx);
    return 0;
}

/* close */
SEC("tracepoint/syscalls/sys_enter_close")
int tracepoint__syscalls__sys_enter_close(struct trace_event_raw_sys_enter *ctx) {
    if (!should_trace()) return 0;
    unsigned int tid = (unsigned int)bpf_get_current_pid_tgid();
    int fd = (int)ctx->args[0];
    bpf_map_update_elem(&pending_closes, &tid, &fd, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_close")
int tracepoint__syscalls__sys_exit_close(struct trace_event_raw_sys_exit *ctx) {
    if (!should_trace()) return 0;
    unsigned int tid = (unsigned int)bpf_get_current_pid_tgid();
    int *fd_ptr = bpf_map_lookup_elem(&pending_closes, &tid);
    if (!fd_ptr) return 0;
    int fd = *fd_ptr;
    bpf_map_delete_elem(&pending_closes, &tid);

    if (ctx->ret == 0) {
        unsigned long long pid = bpf_get_current_pid_tgid() >> 32;
        unsigned long long key = (pid << 32) | fd;
        struct fd_state *fstate = bpf_map_lookup_elem(&fd_states, &key);
        if (fstate) {
            struct kdarshan_file_stats *stats = get_or_create_stats(fstate->path_hash);
            if (stats) {
                unsigned long long now = bpf_ktime_get_ns();
                if (stats->fcounters[POSIX_F_CLOSE_START_TIMESTAMP] == 0) {
                    stats->fcounters[POSIX_F_CLOSE_START_TIMESTAMP] = now;
                }
                stats->fcounters[POSIX_F_CLOSE_END_TIMESTAMP] = now;
            }
            bpf_map_delete_elem(&fd_states, &key);
        }
    }
    return 0;
}

/* read / pread / readv / preadv / preadv2 */
static __always_inline void handle_rw_enter(int fd, long long offset, unsigned long buf_addr) {
    unsigned int tid = (unsigned int)bpf_get_current_pid_tgid();
    struct rw_args args = {};
    args.fd = fd;
    args.offset = offset;
    args.start_ns = bpf_ktime_get_ns();
    args.length = buf_addr; // Store buffer address in length field temporarily
    bpf_map_update_elem(&pending_rws, &tid, &args, BPF_ANY);
}

SEC("tracepoint/syscalls/sys_enter_read")
int tracepoint__syscalls__sys_enter_read(struct trace_event_raw_sys_enter *ctx) {
    if (!should_trace()) return 0;
    int fd = (int)ctx->args[0];
    handle_rw_enter(fd, get_file_pos(fd), ctx->args[1]);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_pread64")
int tracepoint__syscalls__sys_enter_pread64(struct trace_event_raw_sys_enter *ctx) {
    if (!should_trace()) return 0;
    int fd = (int)ctx->args[0];
    handle_rw_enter(fd, ctx->args[3], ctx->args[1]);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_readv")
int tracepoint__syscalls__sys_enter_readv(struct trace_event_raw_sys_enter *ctx) {
    if (!should_trace()) return 0;
    int fd = (int)ctx->args[0];
    handle_rw_enter(fd, get_file_pos(fd), ctx->args[1]);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_preadv")
int tracepoint__syscalls__sys_enter_preadv(struct trace_event_raw_sys_enter *ctx) {
    if (!should_trace()) return 0;
    int fd = (int)ctx->args[0];
    handle_rw_enter(fd, ctx->args[3], ctx->args[1]);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_preadv2")
int tracepoint__syscalls__sys_enter_preadv2(struct trace_event_raw_sys_enter *ctx) {
    if (!should_trace()) return 0;
    int fd = (int)ctx->args[0];
    handle_rw_enter(fd, ctx->args[3], ctx->args[1]);
    return 0;
}

/* write / pwrite / writev / pwritev / pwritev2 */
SEC("tracepoint/syscalls/sys_enter_write")
int tracepoint__syscalls__sys_enter_write(struct trace_event_raw_sys_enter *ctx) {
    if (!should_trace()) return 0;
    int fd = (int)ctx->args[0];
    handle_rw_enter(fd, get_file_pos(fd), ctx->args[1]);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_pwrite64")
int tracepoint__syscalls__sys_enter_pwrite64(struct trace_event_raw_sys_enter *ctx) {
    if (!should_trace()) return 0;
    int fd = (int)ctx->args[0];
    handle_rw_enter(fd, ctx->args[3], ctx->args[1]);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_writev")
int tracepoint__syscalls__sys_enter_writev(struct trace_event_raw_sys_enter *ctx) {
    if (!should_trace()) return 0;
    int fd = (int)ctx->args[0];
    handle_rw_enter(fd, get_file_pos(fd), ctx->args[1]);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_pwritev")
int tracepoint__syscalls__sys_enter_pwritev(struct trace_event_raw_sys_enter *ctx) {
    if (!should_trace()) return 0;
    int fd = (int)ctx->args[0];
    handle_rw_enter(fd, ctx->args[3], ctx->args[1]);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_pwritev2")
int tracepoint__syscalls__sys_enter_pwritev2(struct trace_event_raw_sys_enter *ctx) {
    if (!should_trace()) return 0;
    int fd = (int)ctx->args[0];
    handle_rw_enter(fd, ctx->args[3], ctx->args[1]);
    return 0;
}

static __always_inline void handle_rw_exit(struct trace_event_raw_sys_exit *ctx, int write_flag) {
    unsigned int tid = (unsigned int)bpf_get_current_pid_tgid();
    struct rw_args *args = bpf_map_lookup_elem(&pending_rws, &tid);
    if (!args) return;

    long long ret = ctx->ret;
    if (ret > 0) {
        unsigned long long pid = bpf_get_current_pid_tgid() >> 32;
        unsigned long long key = (pid << 32) | args->fd;
        struct fd_state *fstate = bpf_map_lookup_elem(&fd_states, &key);
        if (fstate) {
            unsigned long long path_hash = fstate->path_hash;
            struct kdarshan_file_stats *stats = get_or_create_stats(path_hash);
            if (stats) {
                unsigned long long now = bpf_ktime_get_ns();
                unsigned long long elapsed = now - args->start_ns;

                long long this_offset = args->offset;
                long long length = ret;
                unsigned long buf_addr = args->length;

                if (write_flag) {
                    stats->counters[POSIX_WRITES] += 1;
                    stats->counters[POSIX_BYTES_WRITTEN] += length;
                    
                    if (stats->fcounters[POSIX_F_WRITE_START_TIMESTAMP] == 0 ||
                        stats->fcounters[POSIX_F_WRITE_START_TIMESTAMP] > args->start_ns) {
                        stats->fcounters[POSIX_F_WRITE_START_TIMESTAMP] = args->start_ns;
                    }
                    stats->fcounters[POSIX_F_WRITE_END_TIMESTAMP] = now;
                    stats->fcounters[POSIX_F_WRITE_TIME] += elapsed;
                    if (stats->fcounters[POSIX_F_MAX_WRITE_TIME] < elapsed) {
                        stats->fcounters[POSIX_F_MAX_WRITE_TIME] = elapsed;
                        stats->counters[POSIX_MAX_WRITE_TIME_SIZE] = length;
                    }

                    long long end_byte = this_offset + length - 1;
                    if (stats->counters[POSIX_MAX_BYTE_WRITTEN] < end_byte) {
                        stats->counters[POSIX_MAX_BYTE_WRITTEN] = end_byte;
                    }

                    if (this_offset > fstate->last_byte_written) {
                        stats->counters[POSIX_SEQ_WRITES] += 1;
                    }
                    if (this_offset == (fstate->last_byte_written + 1)) {
                        stats->counters[POSIX_CONSEC_WRITES] += 1;
                    }

                    fstate->last_byte_written = end_byte;

                    if (fstate->last_io_type == 1) {
                        stats->counters[POSIX_RW_SWITCHES] += 1;
                    }
                    fstate->last_io_type = 2;

                    // Buckets
                    if (length <= 100) stats->counters[POSIX_SIZE_WRITE_0_100]++;
                    else if (length <= 1024) stats->counters[POSIX_SIZE_WRITE_100_1K]++;
                    else if (length <= 10240) stats->counters[POSIX_SIZE_WRITE_1K_10K]++;
                    else if (length <= 102400) stats->counters[POSIX_SIZE_WRITE_10K_100K]++;
                    else if (length <= 1048576) stats->counters[POSIX_SIZE_WRITE_100K_1M]++;
                    else if (length <= 4194304) stats->counters[POSIX_SIZE_WRITE_1M_4M]++;
                    else if (length <= 10485760) stats->counters[POSIX_SIZE_WRITE_4M_10M]++;
                    else if (length <= 104857600) stats->counters[POSIX_SIZE_WRITE_10M_100M]++;
                    else if (length <= 1073741824) stats->counters[POSIX_SIZE_WRITE_100M_1G]++;
                    else stats->counters[POSIX_SIZE_WRITE_1G_PLUS]++;
                } else {
                    stats->counters[POSIX_READS] += 1;
                    stats->counters[POSIX_BYTES_READ] += length;
                    
                    if (stats->fcounters[POSIX_F_READ_START_TIMESTAMP] == 0 ||
                        stats->fcounters[POSIX_F_READ_START_TIMESTAMP] > args->start_ns) {
                        stats->fcounters[POSIX_F_READ_START_TIMESTAMP] = args->start_ns;
                    }
                    stats->fcounters[POSIX_F_READ_END_TIMESTAMP] = now;
                    stats->fcounters[POSIX_F_READ_TIME] += elapsed;
                    if (stats->fcounters[POSIX_F_MAX_READ_TIME] < elapsed) {
                        stats->fcounters[POSIX_F_MAX_READ_TIME] = elapsed;
                        stats->counters[POSIX_MAX_READ_TIME_SIZE] = length;
                    }

                    long long end_byte = this_offset + length - 1;
                    if (stats->counters[POSIX_MAX_BYTE_READ] < end_byte) {
                        stats->counters[POSIX_MAX_BYTE_READ] = end_byte;
                    }

                    if (this_offset > fstate->last_byte_read) {
                        stats->counters[POSIX_SEQ_READS] += 1;
                    }
                    if (this_offset == (fstate->last_byte_read + 1)) {
                        stats->counters[POSIX_CONSEC_READS] += 1;
                    }

                    fstate->last_byte_read = end_byte;

                    if (fstate->last_io_type == 2) {
                        stats->counters[POSIX_RW_SWITCHES] += 1;
                    }
                    fstate->last_io_type = 1;

                    // Buckets
                    if (length <= 100) stats->counters[POSIX_SIZE_READ_0_100]++;
                    else if (length <= 1024) stats->counters[POSIX_SIZE_READ_100_1K]++;
                    else if (length <= 10240) stats->counters[POSIX_SIZE_READ_1K_10K]++;
                    else if (length <= 102400) stats->counters[POSIX_SIZE_READ_10K_100K]++;
                    else if (length <= 1048576) stats->counters[POSIX_SIZE_READ_100K_1M]++;
                    else if (length <= 4194304) stats->counters[POSIX_SIZE_READ_1M_4M]++;
                    else if (length <= 10485760) stats->counters[POSIX_SIZE_READ_4M_10M]++;
                    else if (length <= 104857600) stats->counters[POSIX_SIZE_READ_10M_100M]++;
                    else if (length <= 1073741824) stats->counters[POSIX_SIZE_READ_100M_1G]++;
                    else stats->counters[POSIX_SIZE_READ_1G_PLUS]++;
                }

                // Alignment Check
                long long file_alignment = stats->counters[POSIX_FILE_ALIGNMENT];
                if (file_alignment > 0 && ((unsigned long long)this_offset % (unsigned long long)file_alignment) != 0) {
                    stats->counters[POSIX_FILE_NOT_ALIGNED] += 1;
                }
                if (buf_addr % 8 != 0) {
                    stats->counters[POSIX_MEM_NOT_ALIGNED] += 1;
                }

                // DXT ring buffer
                struct dxt_event *dxt = bpf_ringbuf_reserve(&dxt_events, sizeof(struct dxt_event), 0);
                if (dxt) {
                    dxt->path_hash = fstate->path_hash;
                    dxt->start_ns = args->start_ns;
                    dxt->end_ns = now;
                    dxt->offset = args->offset;
                    dxt->length = length;
                    dxt->pid = pid;
                    dxt->write_flag = write_flag;
                    bpf_ringbuf_submit(dxt, 0);
                }
            }
        }
    }
    bpf_map_delete_elem(&pending_rws, &tid);
}

SEC("tracepoint/syscalls/sys_exit_read")
int tracepoint__syscalls__sys_exit_read(struct trace_event_raw_sys_exit *ctx) {
    if (!should_trace()) return 0;
    handle_rw_exit(ctx, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_pread64")
int tracepoint__syscalls__sys_exit_pread64(struct trace_event_raw_sys_exit *ctx) {
    if (!should_trace()) return 0;
    handle_rw_exit(ctx, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_readv")
int tracepoint__syscalls__sys_exit_readv(struct trace_event_raw_sys_exit *ctx) {
    if (!should_trace()) return 0;
    handle_rw_exit(ctx, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_preadv")
int tracepoint__syscalls__sys_exit_preadv(struct trace_event_raw_sys_exit *ctx) {
    if (!should_trace()) return 0;
    handle_rw_exit(ctx, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_preadv2")
int tracepoint__syscalls__sys_exit_preadv2(struct trace_event_raw_sys_exit *ctx) {
    if (!should_trace()) return 0;
    handle_rw_exit(ctx, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_write")
int tracepoint__syscalls__sys_exit_write(struct trace_event_raw_sys_exit *ctx) {
    if (!should_trace()) return 0;
    handle_rw_exit(ctx, 1);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_pwrite64")
int tracepoint__syscalls__sys_exit_pwrite64(struct trace_event_raw_sys_exit *ctx) {
    if (!should_trace()) return 0;
    handle_rw_exit(ctx, 1);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_writev")
int tracepoint__syscalls__sys_exit_writev(struct trace_event_raw_sys_exit *ctx) {
    if (!should_trace()) return 0;
    handle_rw_exit(ctx, 1);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_pwritev")
int tracepoint__syscalls__sys_exit_pwritev(struct trace_event_raw_sys_exit *ctx) {
    if (!should_trace()) return 0;
    handle_rw_exit(ctx, 1);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_pwritev2")
int tracepoint__syscalls__sys_exit_pwritev2(struct trace_event_raw_sys_exit *ctx) {
    if (!should_trace()) return 0;
    handle_rw_exit(ctx, 1);
    return 0;
}

/* lseek */
SEC("tracepoint/syscalls/sys_enter_lseek")
int tracepoint__syscalls__sys_enter_lseek(struct trace_event_raw_sys_enter *ctx) {
    if (!should_trace()) return 0;
    unsigned int tid = (unsigned int)bpf_get_current_pid_tgid();
    int fd = (int)ctx->args[0];
    bpf_map_update_elem(&pending_seeks, &tid, &fd, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_lseek")
int tracepoint__syscalls__sys_exit_lseek(struct trace_event_raw_sys_exit *ctx) {
    if (!should_trace()) return 0;
    unsigned int tid = (unsigned int)bpf_get_current_pid_tgid();
    int *fd_ptr = bpf_map_lookup_elem(&pending_seeks, &tid);
    if (!fd_ptr) return 0;
    int fd = *fd_ptr;
    bpf_map_delete_elem(&pending_seeks, &tid);

    if (ctx->ret >= 0) {
        unsigned long long pid = bpf_get_current_pid_tgid() >> 32;
        unsigned long long key = (pid << 32) | fd;
        struct fd_state *fstate = bpf_map_lookup_elem(&fd_states, &key);
        if (fstate) {
            struct kdarshan_file_stats *stats = get_or_create_stats(fstate->path_hash);
            if (stats) {
                stats->counters[POSIX_SEEKS] += 1;
            }
        }
    }
    return 0;
}

/* fsync / fdatasync */
SEC("tracepoint/syscalls/sys_enter_fsync")
int tracepoint__syscalls__sys_enter_fsync(struct trace_event_raw_sys_enter *ctx) {
    if (!should_trace()) return 0;
    unsigned int tid = (unsigned int)bpf_get_current_pid_tgid();
    int fd = (int)ctx->args[0];
    bpf_map_update_elem(&pending_seeks, &tid, &fd, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fsync")
int tracepoint__syscalls__sys_exit_fsync(struct trace_event_raw_sys_exit *ctx) {
    if (!should_trace()) return 0;
    unsigned int tid = (unsigned int)bpf_get_current_pid_tgid();
    int *fd_ptr = bpf_map_lookup_elem(&pending_seeks, &tid);
    if (!fd_ptr) return 0;
    int fd = *fd_ptr;
    bpf_map_delete_elem(&pending_seeks, &tid);

    if (ctx->ret == 0) {
        unsigned long long pid = bpf_get_current_pid_tgid() >> 32;
        unsigned long long key = (pid << 32) | fd;
        struct fd_state *fstate = bpf_map_lookup_elem(&fd_states, &key);
        if (fstate) {
            struct kdarshan_file_stats *stats = get_or_create_stats(fstate->path_hash);
            if (stats) {
                stats->counters[POSIX_FSYNCS] += 1;
            }
        }
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fdatasync")
int tracepoint__syscalls__sys_enter_fdatasync(struct trace_event_raw_sys_enter *ctx) {
    if (!should_trace()) return 0;
    unsigned int tid = (unsigned int)bpf_get_current_pid_tgid();
    int fd = (int)ctx->args[0];
    bpf_map_update_elem(&pending_seeks, &tid, &fd, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fdatasync")
int tracepoint__syscalls__sys_exit_fdatasync(struct trace_event_raw_sys_exit *ctx) {
    if (!should_trace()) return 0;
    unsigned int tid = (unsigned int)bpf_get_current_pid_tgid();
    int *fd_ptr = bpf_map_lookup_elem(&pending_seeks, &tid);
    if (!fd_ptr) return 0;
    int fd = *fd_ptr;
    bpf_map_delete_elem(&pending_seeks, &tid);

    if (ctx->ret == 0) {
        unsigned long long pid = bpf_get_current_pid_tgid() >> 32;
        unsigned long long key = (pid << 32) | fd;
        struct fd_state *fstate = bpf_map_lookup_elem(&fd_states, &key);
        if (fstate) {
            struct kdarshan_file_stats *stats = get_or_create_stats(fstate->path_hash);
            if (stats) {
                stats->counters[POSIX_FDSYNCS] += 1;
            }
        }
    }
    return 0;
}

/* stat / fstat / newfstatat */
SEC("tracepoint/syscalls/sys_enter_newfstat")
int tracepoint__syscalls__sys_enter_newfstat(struct trace_event_raw_sys_enter *ctx) {
    if (!should_trace()) return 0;
    unsigned int tid = (unsigned int)bpf_get_current_pid_tgid();
    int fd = (int)ctx->args[0];
    bpf_map_update_elem(&pending_stats, &tid, &fd, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_newfstat")
int tracepoint__syscalls__sys_exit_newfstat(struct trace_event_raw_sys_exit *ctx) {
    if (!should_trace()) return 0;
    unsigned int tid = (unsigned int)bpf_get_current_pid_tgid();
    int *fd_ptr = bpf_map_lookup_elem(&pending_stats, &tid);
    if (!fd_ptr) return 0;
    int fd = *fd_ptr;
    bpf_map_delete_elem(&pending_stats, &tid);

    if (ctx->ret == 0) {
        unsigned long long pid = bpf_get_current_pid_tgid() >> 32;
        unsigned long long key = (pid << 32) | fd;
        struct fd_state *fstate = bpf_map_lookup_elem(&fd_states, &key);
        if (fstate) {
            struct kdarshan_file_stats *stats = get_or_create_stats(fstate->path_hash);
            if (stats) {
                stats->counters[POSIX_STATS] += 1;
            }
        }
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_newfstatat")
int tracepoint__syscalls__sys_enter_newfstatat(struct trace_event_raw_sys_enter *ctx) {
    if (!should_trace()) return 0;
    unsigned int tid = (unsigned int)bpf_get_current_pid_tgid();
    int fd = (int)ctx->args[0];
    bpf_map_update_elem(&pending_stats, &tid, &fd, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_newfstatat")
int tracepoint__syscalls__sys_exit_newfstatat(struct trace_event_raw_sys_exit *ctx) {
    if (!should_trace()) return 0;
    unsigned int tid = (unsigned int)bpf_get_current_pid_tgid();
    int *fd_ptr = bpf_map_lookup_elem(&pending_stats, &tid);
    if (!fd_ptr) return 0;
    int fd = *fd_ptr;
    bpf_map_delete_elem(&pending_stats, &tid);

    if (ctx->ret == 0) {
        unsigned long long pid = bpf_get_current_pid_tgid() >> 32;
        unsigned long long key = (pid << 32) | fd;
        struct fd_state *fstate = bpf_map_lookup_elem(&fd_states, &key);
        if (fstate) {
            struct kdarshan_file_stats *stats = get_or_create_stats(fstate->path_hash);
            if (stats) {
                stats->counters[POSIX_STATS] += 1;
            }
        }
    }
    return 0;
}

/* dup / dup2 / dup3 */
static __always_inline void handle_dup_enter(int oldfd) {
    unsigned int tid = (unsigned int)bpf_get_current_pid_tgid();
    bpf_map_update_elem(&pending_dups, &tid, &oldfd, BPF_ANY);
}

SEC("tracepoint/syscalls/sys_enter_dup")
int tracepoint__syscalls__sys_enter_dup(struct trace_event_raw_sys_enter *ctx) {
    if (!should_trace()) return 0;
    handle_dup_enter((int)ctx->args[0]);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_dup2")
int tracepoint__syscalls__sys_enter_dup2(struct trace_event_raw_sys_enter *ctx) {
    if (!should_trace()) return 0;
    handle_dup_enter((int)ctx->args[0]);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_dup3")
int tracepoint__syscalls__sys_enter_dup3(struct trace_event_raw_sys_enter *ctx) {
    if (!should_trace()) return 0;
    handle_dup_enter((int)ctx->args[0]);
    return 0;
}

static __always_inline void handle_dup_exit(struct trace_event_raw_sys_exit *ctx) {
    unsigned int tid = (unsigned int)bpf_get_current_pid_tgid();
    int *oldfd_ptr = bpf_map_lookup_elem(&pending_dups, &tid);
    if (!oldfd_ptr) return;
    int oldfd = *oldfd_ptr;
    bpf_map_delete_elem(&pending_dups, &tid);

    long newfd = ctx->ret;
    if (newfd >= 0) {
        unsigned long long pid = bpf_get_current_pid_tgid() >> 32;
        unsigned long long old_key = (pid << 32) | oldfd;
        struct fd_state *old_fstate = bpf_map_lookup_elem(&fd_states, &old_key);
        if (old_fstate) {
            struct fd_state new_fstate = *old_fstate;
            unsigned long long new_key = (pid << 32) | newfd;
            bpf_map_update_elem(&fd_states, &new_key, &new_fstate, BPF_ANY);

            struct kdarshan_file_stats *stats = get_or_create_stats(old_fstate->path_hash);
            if (stats) {
                stats->counters[POSIX_DUPS] += 1;
                stats->counters[POSIX_OPENS] += 1; // As per Darshan spec
            }
        }
    }
}

SEC("tracepoint/syscalls/sys_exit_dup")
int tracepoint__syscalls__sys_exit_dup(struct trace_event_raw_sys_exit *ctx) {
    if (!should_trace()) return 0;
    handle_dup_exit(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_dup2")
int tracepoint__syscalls__sys_exit_dup2(struct trace_event_raw_sys_exit *ctx) {
    if (!should_trace()) return 0;
    handle_dup_exit(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_dup3")
int tracepoint__syscalls__sys_exit_dup3(struct trace_event_raw_sys_exit *ctx) {
    if (!should_trace()) return 0;
    handle_dup_exit(ctx);
    return 0;
}

/* fcntl */
SEC("tracepoint/syscalls/sys_enter_fcntl")
int tracepoint__syscalls__sys_enter_fcntl(struct trace_event_raw_sys_enter *ctx) {
    if (!should_trace()) return 0;
    int cmd = (int)ctx->args[1];
    if (cmd == F_DUPFD || cmd == F_DUPFD_CLOEXEC) {
        unsigned int tid = (unsigned int)bpf_get_current_pid_tgid();
        struct { int fd; int cmd; } fargs = { (int)ctx->args[0], cmd };
        bpf_map_update_elem(&pending_fcnl, &tid, &fargs, BPF_ANY);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fcntl")
int tracepoint__syscalls__sys_exit_fcntl(struct trace_event_raw_sys_exit *ctx) {
    if (!should_trace()) return 0;
    unsigned int tid = (unsigned int)bpf_get_current_pid_tgid();
    struct { int fd; int cmd; } *fargs = bpf_map_lookup_elem(&pending_fcnl, &tid);
    if (!fargs) return 0;
    int oldfd = fargs->fd;
    bpf_map_delete_elem(&pending_fcnl, &tid);

    long newfd = ctx->ret;
    if (newfd >= 0) {
        unsigned long long pid = bpf_get_current_pid_tgid() >> 32;
        unsigned long long old_key = (pid << 32) | oldfd;
        struct fd_state *old_fstate = bpf_map_lookup_elem(&fd_states, &old_key);
        if (old_fstate) {
            struct fd_state new_fstate = *old_fstate;
            unsigned long long new_key = (pid << 32) | newfd;
            bpf_map_update_elem(&fd_states, &new_key, &new_fstate, BPF_ANY);

            struct kdarshan_file_stats *stats = get_or_create_stats(old_fstate->path_hash);
            if (stats) {
                stats->counters[POSIX_DUPS] += 1;
                stats->counters[POSIX_OPENS] += 1;
            }
        }
    }
    return 0;
}

/* mmap */
SEC("tracepoint/syscalls/sys_enter_mmap")
int tracepoint__syscalls__sys_enter_mmap(struct trace_event_raw_sys_enter *ctx) {
    if (!should_trace()) return 0;
    unsigned int tid = (unsigned int)bpf_get_current_pid_tgid();
    int fd = (int)ctx->args[4];
    bpf_map_update_elem(&pending_seeks, &tid, &fd, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_mmap")
int tracepoint__syscalls__sys_exit_mmap(struct trace_event_raw_sys_exit *ctx) {
    if (!should_trace()) return 0;
    unsigned int tid = (unsigned int)bpf_get_current_pid_tgid();
    int *fd_ptr = bpf_map_lookup_elem(&pending_seeks, &tid);
    if (!fd_ptr) return 0;
    int fd = *fd_ptr;
    bpf_map_delete_elem(&pending_seeks, &tid);

    if (ctx->ret != -1 && fd >= 0) {
        unsigned long long pid = bpf_get_current_pid_tgid() >> 32;
        unsigned long long key = (pid << 32) | fd;
        struct fd_state *fstate = bpf_map_lookup_elem(&fd_states, &key);
        if (fstate) {
            struct kdarshan_file_stats *stats = get_or_create_stats(fstate->path_hash);
            if (stats) {
                stats->counters[POSIX_MMAPS] += 1;
            }
        }
    }
    return 0;
}
