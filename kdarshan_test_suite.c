#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <string.h>

#define ALIGNMENT 8

int main() {
    // 1. Wait for tracer to attach
    printf("Test program started. Waiting for tracer to attach...\n");
    sleep(2);

    // 2. Open file: POSIX_OPENS = 1
    int fd = open("test_suite.bin", O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        perror("open");
        return 1;
    }
    printf("File opened. fd = %d\n", fd);

    // 3. Unaligned memory buffer write: POSIX_MEM_NOT_ALIGNED = 1
    // buf starts on an aligned address, we offset by 1 to make it unaligned.
    char *raw_buf = malloc(64);
    if (!raw_buf) {
        perror("malloc");
        return 1;
    }
    char *unaligned_buf = raw_buf + 1; // Unaligned to 8 bytes
    memset(raw_buf, 'A', 64);

    // Write 10 bytes at offset 0 (aligned offset, unaligned memory)
    // POSIX_WRITES = 1, POSIX_BYTES_WRITTEN = 10, POSIX_MEM_NOT_ALIGNED = 1
    if (write(fd, unaligned_buf, 10) != 10) {
        perror("write 1");
    }

    // 4. Unaligned file offset write: POSIX_FILE_NOT_ALIGNED = 1
    // Seek to offset 5: POSIX_SEEKS = 1
    if (lseek(fd, 5, SEEK_SET) != 5) {
        perror("lseek 1");
    }
    // Write 16 bytes using aligned memory pointer raw_buf (since raw_buf is aligned by malloc to at least 8/16 bytes)
    // POSIX_WRITES = 2, POSIX_BYTES_WRITTEN = 26, POSIX_FILE_NOT_ALIGNED = 1
    // Last byte written becomes 5 + 16 - 1 = 20.
    if (write(fd, raw_buf, 16) != 16) {
        perror("write 2");
    }

    // 5. Sequential / Consecutive write: POSIX_SEQ_WRITES = 1, POSIX_CONSEC_WRITES = 1
    // Next write is at offset 21 (contiguous).
    // POSIX_WRITES = 3, POSIX_BYTES_WRITTEN = 46, POSIX_FILE_NOT_ALIGNED = 2, SEQ_WRITES = 1, CONSEC_WRITES = 1
    // Last byte written becomes 21 + 20 - 1 = 40.
    if (write(fd, raw_buf, 20) != 20) {
        perror("write 3");
    }

    // 6. R/W Switches: POSIX_RW_SWITCHES = 2
    // Read at offset 0: POSIX_SEEKS = 2 (lseek to 0)
    if (lseek(fd, 0, SEEK_SET) != 0) {
        perror("lseek 2");
    }
    // POSIX_READS = 1, POSIX_BYTES_READ = 10, POSIX_RW_SWITCHES = 1 (Write to Read)
    char read_buf[16];
    if (read(fd, read_buf, 10) != 10) {
        perror("read 1");
    }

    // Write at current offset 10:
    // POSIX_WRITES = 4, POSIX_BYTES_WRITTEN = 56, POSIX_RW_SWITCHES = 2 (Read to Write)
    if (write(fd, raw_buf, 10) != 10) {
        perror("write 4");
    }

    // 7. Fsync & Fdatasync: POSIX_FSYNCS = 1, POSIX_FDSYNCS = 1
    if (fsync(fd) < 0) {
        perror("fsync");
    }
    if (fdatasync(fd) < 0) {
        perror("fdatasync");
    }

    // 8. Stats: POSIX_STATS = 1
    struct stat st;
    if (fstat(fd, &st) < 0) {
        perror("fstat");
    }

    // 9. Dup: POSIX_DUPS = 1
    int fd_dup = dup(fd);
    if (fd_dup < 0) {
        perror("dup");
    }

    // 10. Mmap: POSIX_MMAPS = 1
    void *map = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) {
        perror("mmap");
    } else {
        printf("mmap succeeded\n");
        munmap(map, 4096);
    }

    // 11. Close:
    if (fd_dup >= 0) {
        close(fd_dup);
    }
    close(fd);
    free(raw_buf);

    printf("Test operations completed. Waiting for logs to drain...\n");
    sleep(2);
    return 0;
}
