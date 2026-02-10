#include <stdio.h>
#include <stdlib.h>
#include <sys/utsname.h>
#include <liburing.h>
#include <liburing/io_uring.h>

static const char *op_strs[] = {
        "IORING_OP_NOP",
        "IORING_OP_READV",
        "IORING_OP_WRITEV",
        "IORING_OP_FSYNC",
        "IORING_OP_READ_FIXED",
        "IORING_OP_WRITE_FIXED",
        "IORING_OP_POLL_ADD",
        "IORING_OP_POLL_REMOVE",
        "IORING_OP_SYNC_FILE_RANGE",
        "IORING_OP_SENDMSG",
        "IORING_OP_RECVMSG",
        "IORING_OP_TIMEOUT",
        "IORING_OP_TIMEOUT_REMOVE",
        "IORING_OP_ACCEPT",
        "IORING_OP_ASYNC_CANCEL",
        "IORING_OP_LINK_TIMEOUT",
        "IORING_OP_CONNECT",
        "IORING_OP_FALLOCATE",
        "IORING_OP_OPENAT",
        "IORING_OP_CLOSE",
        "IORING_OP_FILES_UPDATE",
        "IORING_OP_STATX",
        "IORING_OP_READ",
        "IORING_OP_WRITE",
        "IORING_OP_FADVISE",
        "IORING_OP_MADVISE",
        "IORING_OP_SEND",
        "IORING_OP_RECV",
        "IORING_OP_OPENAT2",
        "IORING_OP_EPOLL_CTL",
        "IORING_OP_SPLICE",
        "IORING_OP_PROVIDE_BUFFERS",
        "IORING_OP_REMOVE_BUFFERS",
        "IORING_OP_TEE",
        "IORING_OP_SHUTDOWN",
        "IORING_OP_RENAMEAT",
        "IORING_OP_UNLINKAT",
        "IORING_OP_MKDIRAT",
        "IORING_OP_SYMLINKAT",
        "IORING_OP_LINKAT",
        "IORING_OP_MSG_RING",
        "IORING_OP_FSETXATTR",
        "IORING_OP_SETXATTR",
        "IORING_OP_FGETXATTR",
        "IORING_OP_GETXATTR",
        "IORING_OP_SOCKET",
        "IORING_OP_URING_CMD",
        "IORING_OP_SEND_ZC",
        "IORING_OP_SENDMSG_ZC",
        "IORING_OP_READ_MULTISHOT",
        "IORING_OP_WAITID",
        "IORING_OP_FUTEX_WAIT",
        "IORING_OP_FUTEX_WAKE",
        "IORING_OP_FUTEX_WAITV",
        "IORING_OP_FIXED_FD_INSTALL",
        "IORING_OP_FTRUNCATE",
        "IORING_OP_BIND",
        "IORING_OP_LISTEN",
};

int main() {
    struct utsname u;
    uname(&u);
    printf("You are running kernel version: %s\n", u.release);
    printf("This program won't work on kernel versions earlier than 5.6\n");
    struct io_uring_probe *probe = io_uring_get_probe();
    printf("Report of your kernel's list of supported io_uring operations:\n");
    for (char i = 0; i < IORING_OP_LAST; i++ ) {
        printf("%s: ", op_strs[i]);
        if(io_uring_opcode_supported(probe, i))
            printf("yes.\n");
        else
            printf("no.\n");

    }
    free(probe);
    return 0;
}
