#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <stdarg.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
#include <map>
#include <sys/stat.h>
#include <dirent.h>
#include <algorithm>


// libbpf headers
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

// bcc headers
#include <bcc/BPF.h>

#include "eauditk.h"
#include "dlogger.h"
#include "kdarshan.h"
#include "kdarshan.skel.h"
#include "eauditd.h"

static volatile bool exiting = false;
static unsigned long long start_ns_monotonic = 0;

static void sig_handler(int sig) {
    exiting = true;
}

// Simple path map
static std::map<unsigned long long, std::string> path_map;

static std::map<unsigned long long, std::string> cgroup_path_cache;

static bool find_cgroup_path_recursive(const std::string& current_dir, unsigned long long target_ino, std::string& resolved_path) {
    DIR* dir = opendir(current_dir.c_str());
    if (!dir) return false;
    
    struct dirent* entry;
    std::vector<std::string> subdirs;
    while ((entry = readdir(dir)) != nullptr) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        if (entry->d_type == DT_DIR) {
            std::string path = current_dir;
            if (path.back() != '/') path += "/";
            path += entry->d_name;
            
            struct stat st;
            if (stat(path.c_str(), &st) == 0) {
                if (st.st_ino == target_ino) {
                    resolved_path = path.substr(14); // len("/sys/fs/cgroup") = 14
                    if (resolved_path.empty()) resolved_path = "/";
                    closedir(dir);
                    return true;
                }
                subdirs.push_back(path);
            }
        }
    }
    closedir(dir);
    
    for (const auto& subdir : subdirs) {
        if (find_cgroup_path_recursive(subdir, target_ino, resolved_path)) {
            return true;
        }
    }
    return false;
}

static std::string get_cgroup_path(unsigned long long cgroup_id, int pid) {
    if (cgroup_path_cache.count(cgroup_id)) {
        return cgroup_path_cache[cgroup_id];
    }
    
    std::string path = "";
    if (pid > 0) {
        char proc_path[128];
        snprintf(proc_path, sizeof(proc_path), "/proc/%d/cgroup", pid);
        std::ifstream f(proc_path);
        if (f.is_open()) {
            std::string line;
            while (std::getline(f, line)) {
                if (line.rfind("0::", 0) == 0) {
                    path = line.substr(3);
                    if (path.empty()) path = "/";
                    break;
                }
            }
        }
    }
    
    if (!path.empty()) {
        std::string full_sys_path = "/sys/fs/cgroup" + path;
        struct stat st;
        if (stat(full_sys_path.c_str(), &st) != 0 || st.st_ino != cgroup_id) {
            path = "";
        }
    }
    
    if (path.empty()) {
        struct stat st_root;
        if (stat("/sys/fs/cgroup", &st_root) == 0 && st_root.st_ino == cgroup_id) {
            path = "/";
        } else {
            find_cgroup_path_recursive("/sys/fs/cgroup", cgroup_id, path);
        }
    }
    
    if (path.empty()) {
        path = "/";
    }
    
    cgroup_path_cache[cgroup_id] = path;
    return path;
}

static void emit_cgroup_path(unsigned long long cgroup_id, const std::string& path) {
    std::vector<char> buf;
    buf.push_back(TS_CGROUP_PATH);
    for (int i = 0; i < 8; ++i) {
        buf.push_back((char)((cgroup_id >> (i * 8)) & 0xff));
    }
    uint8_t len = (uint8_t)std::min((size_t)255, path.length());
    buf.push_back(len);
    for (uint8_t i = 0; i < len; ++i) {
        buf.push_back(path[i]);
    }
    logprinter(nullptr, buf.data(), (int)buf.size());
}

static void scan_and_emit_cgroups() {
    struct stat st_root;
    if (stat("/sys/fs/cgroup", &st_root) == 0) {
        std::string path = "/";
        get_cgroup_path(st_root.st_ino, 0);
        emit_cgroup_path(st_root.st_ino, path);
    }
    
    std::vector<std::string> pending_dirs = {"/sys/fs/cgroup"};
    while (!pending_dirs.empty()) {
        std::string current_dir = pending_dirs.back();
        pending_dirs.pop_back();
        
        DIR* dir = opendir(current_dir.c_str());
        if (!dir) continue;
        
        struct dirent* entry;
        while ((entry = readdir(dir)) != nullptr) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
                continue;
            }
            if (entry->d_type == DT_DIR) {
                std::string path = current_dir;
                if (path.back() != '/') path += "/";
                path += entry->d_name;
                
                struct stat st;
                if (stat(path.c_str(), &st) == 0) {
                    std::string rel_path = path.substr(14);
                    if (rel_path.empty()) rel_path = "/";
                    
                    if (cgroup_path_cache.find(st.st_ino) == cgroup_path_cache.end()) {
                        cgroup_path_cache[st.st_ino] = rel_path;
                        emit_cgroup_path(st.st_ino, rel_path);
                    }
                    pending_dirs.push_back(path);
                }
            }
        }
        closedir(dir);
    }
}


std::vector<std::string> parse_exclude_paths(const char* env_val) {
    std::vector<std::string> paths;
    if (!env_val) return paths;
    std::string s(env_val);
    size_t pos = 0;
    while (true) {
        size_t next = s.find_first_of(",:", pos);
        std::string p = s.substr(pos, next - pos);
        if (!p.empty()) {
            paths.push_back(p);
        }
        if (next == std::string::npos) break;
        pos = next + 1;
    }
    return paths;
}

bool is_excluded(const std::string& path, const std::vector<std::string>& exclude_list) {
    if (path.empty()) return false;
    for (const auto& prefix : exclude_list) {
        if (path.rfind(prefix, 0) == 0) {
            return true;
        }
    }
    return false;
}

// Global exclude path lists
static std::vector<std::string> fine_excludes;

void load_dlogger_config(const std::string& config_path) {
    std::ifstream f(config_path);
    if (!f.is_open()) return;
    std::string line;
    bool fine_cleared = false;
    while (std::getline(f, line)) {
        // Strip comments
        size_t comment_pos = line.find('#');
        if (comment_pos != std::string::npos) {
            line = line.substr(0, comment_pos);
        }
        // Trim
        if (line.empty()) continue;
        size_t first = line.find_first_not_of(" \t\r\n");
        if (first == std::string::npos) continue;
        size_t last = line.find_last_not_of(" \t\r\n");
        line = line.substr(first, (last - first + 1));

        // Tokenize key and val
        size_t delim = line.find_first_of(" \t=");
        if (delim == std::string::npos) continue;
        std::string key = line.substr(0, delim);
        std::string val = line.substr(delim + 1);
        
        // Trim key
        size_t key_last = key.find_last_not_of(" \t=");
        if (key_last != std::string::npos) {
            key = key.substr(0, key_last + 1);
        }
        
        // Trim val
        size_t val_first = val.find_first_not_of(" \t=");
        if (val_first != std::string::npos) {
            val = val.substr(val_first);
        } else {
            val = "";
        }

        if (key == "FINE_EXCLUDE_PATH") {
            if (!fine_cleared) {
                fine_excludes.clear();
                fine_cleared = true;
            }
            std::vector<std::string> parsed = parse_exclude_paths(val.c_str());
            fine_excludes.insert(fine_excludes.end(), parsed.begin(), parsed.end());
        }
    }
}

// DXT events buffering
struct dxt_node {
    struct dxt_event ev;
    dxt_node* next;
};
static dxt_node* dxt_head = nullptr;
static dxt_node* dxt_tail = nullptr;

static int handle_path_event(void *ctx, void *data, size_t data_sz) {
    const struct path_event *e = (const struct path_event *)data;
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
    
    path_map[e->path_hash] = resolved;
    return 0;
}

static int handle_dxt_event(void *ctx, void *data, size_t data_sz) {
    const struct dxt_event *e = (const struct dxt_event *)data;
    if (cgroup_path_cache.find(e->cgroup_id) == cgroup_path_cache.end()) {
        std::string path = get_cgroup_path(e->cgroup_id, e->pid);
        emit_cgroup_path(e->cgroup_id, path);
    }
    dxt_node *node = new dxt_node();
    node->ev = *e;
    node->next = nullptr;
    if (!dxt_head) {
        dxt_head = node;
        dxt_tail = node;
    } else {
        dxt_tail->next = node;
        dxt_tail = node;
    }
    return 0;
}

// BCC eaudit ring buffer callback
static int handle_eaudit_packet(void *cb_cookie, void *data, size_t size) {
    logprinter(nullptr, data, (int)size);
    return 0;
}

// Helper to auto-attach tracepoints in BCC
void auto_attach_tracepoints(ebpf::BPF &bpf, const std::string &src) {
    size_t pos = 0;
    while (true) {
        pos = src.find("TRACEPOINT_PROBE(", pos);
        if (pos == std::string::npos) break;
        pos += 17; // length of "TRACEPOINT_PROBE("
        size_t comma = src.find(",", pos);
        if (comma == std::string::npos) break;
        std::string category = src.substr(pos, comma - pos);
        category.erase(0, category.find_first_not_of(" \t\r\n"));
        category.erase(category.find_last_not_of(" \t\r\n") + 1);

        size_t close_paren = src.find(")", comma);
        if (close_paren == std::string::npos) break;
        std::string event = src.substr(comma + 1, close_paren - (comma + 1));
        event.erase(0, event.find_first_not_of(" \t\r\n"));
        event.erase(event.find_last_not_of(" \t\r\n") + 1);

        std::string tp_name = category + ":" + event;
        std::string fn_name = "tracepoint__" + category + "__" + event;
        // Ignore errors because some tracepoints are compiled out via #ifdefs
        bpf.attach_tracepoint(tp_name, fn_name);
        pos = close_paren;
    }
}

int main(int argc, char **argv) {
    // Set up signal handlers
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // Initialize default exclude lists
    fine_excludes = {"/etc/", "/dev/", "/usr/", "/bin/", "/boot/", "/lib/", "/opt/", "/sbin/", "/sys/", "/proc/", "/var/"};

    // Determine config file path
    std::string config_file_path = "";
    if (argc > 1) {
        config_file_path = argv[1];
    } else {
        // Look in current directory first
        std::ifstream test_conf("dlogger.conf");
        if (test_conf.is_open()) {
            config_file_path = "dlogger.conf";
        } else {
            std::ifstream test_etc("/etc/dlogger.conf");
            if (test_etc.is_open()) {
                config_file_path = "/etc/dlogger.conf";
            }
        }
    }

    if (!config_file_path.empty()) {
        fprintf(stderr, "Loading config file: %s\n", config_file_path.c_str());
        load_dlogger_config(config_file_path);
        fprintf(stderr, "Loaded %zu fine excludes\n", fine_excludes.size());
    } else {
        // Fallback to environment variables if no config file is found
        const char* fine_env = getenv("FINE_EXCLUDE_PATH");
        if (fine_env) {
            fine_excludes = parse_exclude_paths(fine_env);
        }
    }

    // 1. Initialize eaudit C++ daemon
    const char* eaudit_argv[] = {
        "dlogger",
        "1048576",
        "-C", "pg.bin",
        "-l", "2"
    };
    init_consumer(6, eaudit_argv);

    // 2. Load BCC eaudit BPF program
    std::ifstream bpf_file("eauditk.c");
    if (!bpf_file.is_open()) {
        fprintf(stderr, "Failed to open eauditk.c\n");
        return 1;
    }
    std::stringstream buffer;
    buffer << bpf_file.rdbuf();
    std::string eaudit_src_raw = buffer.str();

    // Prepend configurations to eaudit BPF code (mirroring eauditd.py behavior)
    unsigned int pid = getpid();
    int perf_fac = 2;
    int ringbuf_size = 64;
    int push_interval = 5;
    int max_tasks = 1<<13;
    int max_cache_time = 1<<20;
    int WT_THRESH = (1<<10);
    int WT_CRITICAL = (WT_THRESH+1);
    int WT_IMPORTANT = (WT_THRESH >> 1);
    int WT_ENDPOINT = (WT_THRESH >> 5);
    int WT_DGRAM = (WT_THRESH >> 6);
    int WT_FDTRACK = (WT_THRESH >> 7);
    int WT_RDWR = (WT_THRESH >> 8);
    int WT_UNIMPORTANT = (WT_THRESH >> 9);
    int WT_REDUNDANT = (WT_THRESH >> 10);
    unsigned long rseed = 123456789ULL; // simple static seed

    std::string config_headers = "";
    config_headers += "#define TX_THRESH " + std::to_string(perf_fac*1024) + "\n";
    config_headers += "#define TX_WT_THRESH " + std::to_string(WT_THRESH) + "\n";
    config_headers += "#define RINGBUF_PAGES " + std::to_string(ringbuf_size*256) + "\n";
    config_headers += "#define RINGBUF_PUSH_INTERVAL " + std::to_string(push_interval) + "\n";
    config_headers += "#define MAX_TASKS " + std::to_string(max_tasks) + "\n";
    config_headers += "#define WT_THRESH " + std::to_string(WT_THRESH) + "\n";
    config_headers += "#define WT_CRITICAL " + std::to_string(WT_CRITICAL) + "\n";
    config_headers += "#define WT_IMPORTANT " + std::to_string(WT_IMPORTANT) + "\n";
    config_headers += "#define WT_ENDPOINT " + std::to_string(WT_ENDPOINT) + "\n";
    config_headers += "#define WT_DGRAM " + std::to_string(WT_DGRAM) + "\n";
    config_headers += "#define WT_FDTRACK " + std::to_string(WT_FDTRACK) + "\n";
    config_headers += "#define WT_RDWR " + std::to_string(WT_RDWR) + "\n";
    config_headers += "#define WT_UNIMPORTANT " + std::to_string(WT_UNIMPORTANT) + "\n";
    config_headers += "#define WT_REDUNDANT " + std::to_string(WT_REDUNDANT) + "\n";
    config_headers += "#define RSEED " + std::to_string(rseed) + "ul\n";
    config_headers += "#define MAXCACHETIME " + std::to_string(max_cache_time) + "ul\n";
    config_headers += "#define PRINTK_LOG_LEVEL 2\n";
    config_headers += "#define EAUDIT_PID " + std::to_string(pid) + "\n";
    config_headers += "#define NETMASK1 0\n#define NETMASK2 0\n#define NETMASK3 0\n";
    config_headers += "#define NETADDR1 1\n#define NETADDR2 1\n#define NETADDR3 1\n";
    config_headers += "#define NS_TO_LOCAL_EP_EPOCH 36\n";
    config_headers += "#define NS_TO_FOREIGN_EP_EPOCH 40\n";
    config_headers += "#define ID_NOT_FD\n";
    config_headers += "#define NUMCPU " + std::to_string(sysconf(_SC_NPROCESSORS_ONLN)) + "\n";
    config_headers += "#define USE_FLUSH_ALGO_A2\n";
    config_headers += "#define SHORT_SEQNUM\n";

    std::string eaudit_src = config_headers + eaudit_src_raw;

    ebpf::BPF bpf_eaudit;
    auto status = bpf_eaudit.init(eaudit_src);
    if (status.code() != 0) {
        fprintf(stderr, "Failed to compile/load eaudit BPF code: %s\n", status.msg().c_str());
        return 1;
    }

    // Set eaudit tracepoint log level to 0 (enable logging)
    auto log_level_table = bpf_eaudit.get_array_table<int>("log_level");
    log_level_table.update_value(0, 0);

    // Load execve tail calls
    int fd_add_argv = -1, fd_add_envp = -1;
    bpf_eaudit.load_func("add_string_tail_argv", BPF_PROG_TYPE_TRACEPOINT, fd_add_argv);
    bpf_eaudit.load_func("add_string_tail_envp", BPF_PROG_TYPE_TRACEPOINT, fd_add_envp);
    
    auto prog_array = bpf_eaudit.get_prog_table("tailcall");
    prog_array.update_value(0, fd_add_argv); // TAILCALL_ADD_ARGV
    prog_array.update_value(1, fd_add_envp); // TAILCALL_ADD_ENVP

    // Auto-attach eaudit tracepoints
    auto_attach_tracepoints(bpf_eaudit, eaudit_src);

    // Open eaudit ring buffer via libbpf ring buffer API
    auto table_eaudit = bpf_eaudit.get_table("events");
    int fd_eaudit = table_eaudit.get_fd();
    struct ring_buffer *rb_eaudit = ring_buffer__new(fd_eaudit, handle_eaudit_packet, NULL, NULL);
    if (!rb_eaudit) {
        fprintf(stderr, "Failed to open eaudit ring buffer\n");
        return 1;
    }

    // 3. Load kdarshan BPF Skeleton
    struct kdarshan_bpf *skel = kdarshan_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open kdarshan BPF skeleton\n");
        return 1;
    }

    // Pass dlogger pid for descendant self-exclusion
    skel->bss->dlogger_pid = pid;

    int err = kdarshan_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load kdarshan skeleton\n");
        return 1;
    }

    err = kdarshan_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach kdarshan skeleton\n");
        return 1;
    }

    // Setup kdarshan ring buffers
    struct ring_buffer *rb_kdarshan = ring_buffer__new(bpf_map__fd(skel->maps.path_events), handle_path_event, NULL, NULL);
    if (!rb_kdarshan) {
        fprintf(stderr, "Failed to create kdarshan ring buffer\n");
        return 1;
    }

    err = ring_buffer__add(rb_kdarshan, bpf_map__fd(skel->maps.dxt_events), handle_dxt_event, NULL);
    if (err) {
        fprintf(stderr, "Failed to add DXT map to kdarshan ring buffer\n");
        return 1;
    }

    // Record monotonic start time
    struct timespec ts_start;
    clock_gettime(CLOCK_MONOTONIC, &ts_start);
    start_ns_monotonic = (unsigned long long)ts_start.tv_sec * 1000000000ULL + ts_start.tv_nsec;

    scan_and_emit_cgroups();

    fprintf(stderr, "dlogger is running. Press Ctrl-C to stop...\n");

    // 4. Polling loop
    while (!exiting) {
        // Poll kdarshan events
        ring_buffer__poll(rb_kdarshan, 10);
        // Poll eaudit events
        ring_buffer__poll(rb_eaudit, 10);
        // Flush eaudit batch buffer
        dowrite();
    }

    fprintf(stderr, "Shutting down dlogger...\n");

    // Flush remaining events
    ring_buffer__poll(rb_kdarshan, 100);
    ring_buffer__poll(rb_eaudit, 100);
    scan_and_emit_cgroups();
    dowrite();

    // 5. Clean up BPFs
    ring_buffer__free(rb_kdarshan);
    ring_buffer__free(rb_eaudit);
    kdarshan_bpf__destroy(skel);

    // Call eaudit end operations to finalize pg.bin
    end_op();

    // 6. Write fine.csv
    std::ofstream csv_file("fine.csv");
    if (csv_file.is_open()) {
        csv_file << "Wt/Rd,PID,Cgroup_ID,Cgroup_Path,Start_Time,Offset,Length,Start_Sec,End_Sec,Filename\n";
        dxt_node *curr = dxt_head;
        int dxt_count = 0;
        while (curr) {
            dxt_count++;
            std::string filename = path_map[curr->ev.path_hash];
            fprintf(stderr, "DEBUG DXT: count=%d pid=%u hash=%llu filename=%s excluded=%d\n",
                    dxt_count, curr->ev.pid, curr->ev.path_hash, filename.c_str(), is_excluded(filename, fine_excludes));
            if (filename.empty()) filename = "UNKNOWN";

            if (!is_excluded(filename, fine_excludes)) {
                double start_sec = (double)(curr->ev.start_ns - start_ns_monotonic) / 1e9;
                double end_sec = (double)(curr->ev.end_ns - start_ns_monotonic) / 1e9;
                if (start_sec < 0.0) start_sec = 0.0;
                if (end_sec < start_sec) end_sec = start_sec;

                std::string cg_path = cgroup_path_cache[curr->ev.cgroup_id];
                if (cg_path.empty()) cg_path = "/";

                csv_file << (curr->ev.write_flag ? "write" : "read") << ","
                         << curr->ev.pid << ","
                         << curr->ev.cgroup_id << ","
                         << cg_path << ","
                         << curr->ev.start_time << ","
                         << curr->ev.offset << ","
                         << curr->ev.length << ","
                         << start_sec << ","
                         << end_sec << ","
                         << filename << "\n";
            }
            curr = curr->next;
        }
        csv_file.close();
        fprintf(stderr, "Processed %d DXT events, written to fine.csv\n", dxt_count);
    } else {
        fprintf(stderr, "Failed to open fine.csv for writing\n");
    }

    // Clean up lists
    dxt_node *curr = dxt_head;
    while (curr) {
        dxt_node *next = curr->next;
        delete curr;
        curr = next;
    }

    return 0;
}
