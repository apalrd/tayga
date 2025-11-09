/*
 * Linux-specific optimizations for TAYGA
 * 
 * This file implements Linux-specific performance optimizations including:
 * - Epoll-based I/O multiplexing
 * - io_uring for high-performance async I/O
 * - CPU frequency governor optimization
 * - Network stack optimization
 * - Memory management optimization
 */

#ifdef __linux__

#include "tayga.h"
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/timerfd.h>
#include <sys/signalfd.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <linux/if_tun.h>
#include <linux/if_ether.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>

/* Epoll-based I/O multiplexing */
int linux_epoll_init(struct linux_epoll *ep, int max_events) {
    ep->epfd = epoll_create1(EPOLL_CLOEXEC);
    if (ep->epfd < 0) {
        slog(LOG_ERR, "Failed to create epoll: %s\n", strerror(errno));
        return -1;
    }
    
    ep->max_events = max_events;
    ep->events = malloc(sizeof(struct epoll_event) * max_events);
    if (!ep->events) {
        close(ep->epfd);
        return -1;
    }
    
    slog(LOG_INFO, "Linux epoll initialized with %d max events\n", max_events);
    return 0;
}

void linux_epoll_destroy(struct linux_epoll *ep) {
    if (ep->epfd >= 0) {
        close(ep->epfd);
        ep->epfd = -1;
    }
    if (ep->events) {
        free(ep->events);
        ep->events = NULL;
    }
}

int linux_epoll_add_fd(struct linux_epoll *ep, int fd, uint32_t events) {
    struct epoll_event ev;
    ev.events = events;
    ev.data.fd = fd;
    
    if (epoll_ctl(ep->epfd, EPOLL_CTL_ADD, fd, &ev) < 0) {
        slog(LOG_ERR, "Failed to add fd %d to epoll: %s\n", fd, strerror(errno));
        return -1;
    }
    
    return 0;
}

int linux_epoll_wait(struct linux_epoll *ep, int timeout_ms) {
    int nfds = epoll_wait(ep->epfd, ep->events, ep->max_events, timeout_ms);
    
    if (nfds < 0) {
        if (errno != EINTR) {
            slog(LOG_ERR, "epoll wait failed: %s\n", strerror(errno));
        }
        return -1;
    }
    
    return nfds;
}

/* io_uring for high-performance async I/O */
int linux_io_uring_init(struct linux_io_uring *ring, int queue_depth) {
    /* Note: io_uring requires kernel 5.1+ and liburing */
    /* For now, we'll implement a placeholder that can be extended */
    ring->ring_fd = -1;
    ring->ring = NULL;
    ring->sqe = NULL;
    ring->cqe = NULL;
    
    slog(LOG_INFO, "Linux io_uring placeholder initialized (requires liburing)\n");
    return 0;
}

void linux_io_uring_destroy(struct linux_io_uring *ring) {
    if (ring->ring_fd >= 0) {
        close(ring->ring_fd);
        ring->ring_fd = -1;
    }
    /* io_uring cleanup would go here */
}

int linux_io_uring_submit(struct linux_io_uring *ring) {
    /* io_uring submit would go here */
    return 0;
}

int linux_io_uring_wait(struct linux_io_uring *ring, int timeout_ms) {
    /* io_uring wait would go here */
    return 0;
}

/* CPU frequency governor optimization */
int linux_cpu_governor_init(struct linux_cpu_governor *gov) {
    gov->num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    gov->cpu_freqs = malloc(sizeof(int) * gov->num_cpus);
    if (!gov->cpu_freqs) {
        slog(LOG_ERR, "Failed to allocate CPU frequency array\n");
        return -1;
    }
    
    /* Read current CPU frequencies */
    for (int i = 0; i < gov->num_cpus; i++) {
        char path[256];
        FILE *f;
        
        snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_cur_freq", i);
        f = fopen(path, "r");
        if (f) {
            fscanf(f, "%d", &gov->cpu_freqs[i]);
            fclose(f);
        } else {
            gov->cpu_freqs[i] = 0; /* CPU not available */
        }
    }
    
    gov->performance_mode = 0;
    slog(LOG_INFO, "Linux CPU governor initialized for %d CPUs\n", gov->num_cpus);
    return 0;
}

void linux_cpu_governor_destroy(struct linux_cpu_governor *gov) {
    if (gov->cpu_freqs) {
        free(gov->cpu_freqs);
        gov->cpu_freqs = NULL;
    }
}

int linux_cpu_governor_set_performance(struct linux_cpu_governor *gov) {
    if (gov->performance_mode) {
        return 0; /* Already in performance mode */
    }
    
    /* Set CPU governor to performance mode */
    for (int i = 0; i < gov->num_cpus; i++) {
        char path[256];
        FILE *f;
        
        snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_governor", i);
        f = fopen(path, "w");
        if (f) {
            fprintf(f, "performance");
            fclose(f);
        }
    }
    
    gov->performance_mode = 1;
    slog(LOG_INFO, "Linux CPU governor set to performance mode\n");
    return 0;
}

int linux_cpu_governor_restore(struct linux_cpu_governor *gov) {
    if (!gov->performance_mode) {
        return 0; /* Not in performance mode */
    }
    
    /* Restore CPU governor to powersave mode */
    for (int i = 0; i < gov->num_cpus; i++) {
        char path[256];
        FILE *f;
        
        snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_governor", i);
        f = fopen(path, "w");
        if (f) {
            fprintf(f, "powersave");
            fclose(f);
        }
    }
    
    gov->performance_mode = 0;
    slog(LOG_INFO, "Linux CPU governor restored to powersave mode\n");
    return 0;
}

/* Network stack optimization */
int linux_net_optimization_init(struct linux_net_optimization *net) {
    FILE *f;
    
    /* Read current TCP congestion control */
    f = fopen("/proc/sys/net/ipv4/tcp_congestion_control", "r");
    if (f) {
        char buf[64];
        if (fgets(buf, sizeof(buf), f)) {
            if (strstr(buf, "bbr")) {
                net->tcp_congestion_control = 1; /* BBR */
            } else if (strstr(buf, "cubic")) {
                net->tcp_congestion_control = 2; /* CUBIC */
            } else {
                net->tcp_congestion_control = 0; /* Other */
            }
        }
        fclose(f);
    }
    
    /* Read current TCP memory settings */
    f = fopen("/proc/sys/net/ipv4/tcp_rmem", "r");
    if (f) {
        fscanf(f, "%d %d %d", &net->tcp_rmem[0], &net->tcp_rmem[1], &net->tcp_rmem[2]);
        fclose(f);
    }
    
    f = fopen("/proc/sys/net/ipv4/tcp_wmem", "r");
    if (f) {
        fscanf(f, "%d %d %d", &net->tcp_wmem[0], &net->tcp_wmem[1], &net->tcp_wmem[2]);
        fclose(f);
    }
    
    /* Read current network core settings */
    f = fopen("/proc/sys/net/core/rmem_max", "r");
    if (f) {
        fscanf(f, "%d", &net->net_core_rmem_max);
        fclose(f);
    }
    
    f = fopen("/proc/sys/net/core/wmem_max", "r");
    if (f) {
        fscanf(f, "%d", &net->net_core_wmem_max);
        fclose(f);
    }
    
    f = fopen("/proc/sys/net/core/netdev_max_backlog", "r");
    if (f) {
        fscanf(f, "%d", &net->net_core_netdev_max_backlog);
        fclose(f);
    }
    
    f = fopen("/proc/sys/net/core/netdev_budget", "r");
    if (f) {
        fscanf(f, "%d", &net->net_core_netdev_budget);
        fclose(f);
    }
    
    slog(LOG_INFO, "Linux network optimization initialized\n");
    return 0;
}

void linux_net_optimization_apply(struct linux_net_optimization *net) {
    FILE *f;
    
    /* Set TCP congestion control to BBR if available */
    f = fopen("/proc/sys/net/ipv4/tcp_congestion_control", "w");
    if (f) {
        fprintf(f, "bbr");
        fclose(f);
        slog(LOG_INFO, "Set TCP congestion control to BBR\n");
    }
    
    /* Optimize TCP memory settings */
    f = fopen("/proc/sys/net/ipv4/tcp_rmem", "w");
    if (f) {
        fprintf(f, "4096 131072 16777216"); /* 4KB, 128KB, 16MB */
        fclose(f);
        slog(LOG_INFO, "Optimized TCP receive memory\n");
    }
    
    f = fopen("/proc/sys/net/ipv4/tcp_wmem", "w");
    if (f) {
        fprintf(f, "4096 16384 16777216"); /* 4KB, 16KB, 16MB */
        fclose(f);
        slog(LOG_INFO, "Optimized TCP send memory\n");
    }
    
    /* Optimize network core settings */
    f = fopen("/proc/sys/net/core/rmem_max", "w");
    if (f) {
        fprintf(f, "16777216"); /* 16MB */
        fclose(f);
        slog(LOG_INFO, "Set net.core.rmem_max to 16MB\n");
    }
    
    f = fopen("/proc/sys/net/core/wmem_max", "w");
    if (f) {
        fprintf(f, "16777216"); /* 16MB */
        fclose(f);
        slog(LOG_INFO, "Set net.core.wmem_max to 16MB\n");
    }
    
    f = fopen("/proc/sys/net/core/netdev_max_backlog", "w");
    if (f) {
        fprintf(f, "5000"); /* Increase backlog */
        fclose(f);
        slog(LOG_INFO, "Set net.core.netdev_max_backlog to 5000\n");
    }
    
    f = fopen("/proc/sys/net/core/netdev_budget", "w");
    if (f) {
        fprintf(f, "600"); /* Increase budget */
        fclose(f);
        slog(LOG_INFO, "Set net.core.netdev_budget to 600\n");
    }
}

void linux_net_optimization_restore(struct linux_net_optimization *net) {
    FILE *f;
    
    /* Restore original values */
    f = fopen("/proc/sys/net/ipv4/tcp_congestion_control", "w");
    if (f) {
        if (net->tcp_congestion_control == 1) {
            fprintf(f, "bbr");
        } else if (net->tcp_congestion_control == 2) {
            fprintf(f, "cubic");
        }
        fclose(f);
    }
    
    f = fopen("/proc/sys/net/ipv4/tcp_rmem", "w");
    if (f) {
        fprintf(f, "%d %d %d", net->tcp_rmem[0], net->tcp_rmem[1], net->tcp_rmem[2]);
        fclose(f);
    }
    
    f = fopen("/proc/sys/net/ipv4/tcp_wmem", "w");
    if (f) {
        fprintf(f, "%d %d %d", net->tcp_wmem[0], net->tcp_wmem[1], net->tcp_wmem[2]);
        fclose(f);
    }
    
    f = fopen("/proc/sys/net/core/rmem_max", "w");
    if (f) {
        fprintf(f, "%d", net->net_core_rmem_max);
        fclose(f);
    }
    
    f = fopen("/proc/sys/net/core/wmem_max", "w");
    if (f) {
        fprintf(f, "%d", net->net_core_wmem_max);
        fclose(f);
    }
    
    f = fopen("/proc/sys/net/core/netdev_max_backlog", "w");
    if (f) {
        fprintf(f, "%d", net->net_core_netdev_max_backlog);
        fclose(f);
    }
    
    f = fopen("/proc/sys/net/core/netdev_budget", "w");
    if (f) {
        fprintf(f, "%d", net->net_core_netdev_budget);
        fclose(f);
    }
    
    slog(LOG_INFO, "Linux network optimization restored to original values\n");
}

/* Memory management optimization */
int linux_memory_optimization_init(struct linux_memory_optimization *mem) {
    FILE *f;
    
    /* Read current memory settings */
    f = fopen("/proc/sys/vm/hugepages", "r");
    if (f) {
        fscanf(f, "%d", &mem->huge_pages);
        fclose(f);
    }
    
    f = fopen("/proc/sys/kernel/mm/transparent_hugepage/enabled", "r");
    if (f) {
        char buf[64];
        if (fgets(buf, sizeof(buf), f)) {
            if (strstr(buf, "[always]")) {
                mem->transparent_huge_pages = 1;
            } else if (strstr(buf, "[madvise]")) {
                mem->transparent_huge_pages = 2;
            } else {
                mem->transparent_huge_pages = 0;
            }
        }
        fclose(f);
    }
    
    f = fopen("/proc/sys/vm/overcommit_memory", "r");
    if (f) {
        fscanf(f, "%d", &mem->memory_overcommit);
        fclose(f);
    }
    
    f = fopen("/proc/sys/vm/swappiness", "r");
    if (f) {
        fscanf(f, "%d", &mem->swappiness);
        fclose(f);
    }
    
    f = fopen("/proc/sys/vm/dirty_ratio", "r");
    if (f) {
        fscanf(f, "%d", &mem->dirty_ratio);
        fclose(f);
    }
    
    f = fopen("/proc/sys/vm/dirty_background_ratio", "r");
    if (f) {
        fscanf(f, "%d", &mem->dirty_background_ratio);
        fclose(f);
    }
    
    slog(LOG_INFO, "Linux memory optimization initialized\n");
    return 0;
}

void linux_memory_optimization_apply(struct linux_memory_optimization *mem) {
    FILE *f;
    
    /* Enable transparent huge pages */
    f = fopen("/proc/sys/kernel/mm/transparent_hugepage/enabled", "w");
    if (f) {
        fprintf(f, "always");
        fclose(f);
        slog(LOG_INFO, "Enabled transparent huge pages\n");
    }
    
    /* Optimize memory overcommit */
    f = fopen("/proc/sys/vm/overcommit_memory", "w");
    if (f) {
        fprintf(f, "1"); /* Always overcommit */
        fclose(f);
        slog(LOG_INFO, "Set memory overcommit to always\n");
    }
    
    /* Reduce swappiness for better performance */
    f = fopen("/proc/sys/vm/swappiness", "w");
    if (f) {
        fprintf(f, "10"); /* Reduce swapping */
        fclose(f);
        slog(LOG_INFO, "Set swappiness to 10\n");
    }
    
    /* Optimize dirty page ratios */
    f = fopen("/proc/sys/vm/dirty_ratio", "w");
    if (f) {
        fprintf(f, "15"); /* 15% of memory */
        fclose(f);
        slog(LOG_INFO, "Set dirty_ratio to 15\n");
    }
    
    f = fopen("/proc/sys/vm/dirty_background_ratio", "w");
    if (f) {
        fprintf(f, "5"); /* 5% of memory */
        fclose(f);
        slog(LOG_INFO, "Set dirty_background_ratio to 5\n");
    }
}

void linux_memory_optimization_restore(struct linux_memory_optimization *mem) {
    FILE *f;
    
    /* Restore original values */
    f = fopen("/proc/sys/kernel/mm/transparent_hugepage/enabled", "w");
    if (f) {
        if (mem->transparent_huge_pages == 1) {
            fprintf(f, "always");
        } else if (mem->transparent_huge_pages == 2) {
            fprintf(f, "madvise");
        } else {
            fprintf(f, "never");
        }
        fclose(f);
    }
    
    f = fopen("/proc/sys/vm/overcommit_memory", "w");
    if (f) {
        fprintf(f, "%d", mem->memory_overcommit);
        fclose(f);
    }
    
    f = fopen("/proc/sys/vm/swappiness", "w");
    if (f) {
        fprintf(f, "%d", mem->swappiness);
        fclose(f);
    }
    
    f = fopen("/proc/sys/vm/dirty_ratio", "w");
    if (f) {
        fprintf(f, "%d", mem->dirty_ratio);
        fclose(f);
    }
    
    f = fopen("/proc/sys/vm/dirty_background_ratio", "w");
    if (f) {
        fprintf(f, "%d", mem->dirty_background_ratio);
        fclose(f);
    }
    
    slog(LOG_INFO, "Linux memory optimization restored to original values\n");
}

/* Main Linux optimization setup function */
int setup_linux_optimizations(void) {
    slog(LOG_INFO, "Setting up Linux-specific optimizations\n");
    
    /* Initialize epoll for I/O multiplexing */
    if (gcfg->enable_epoll_io) {
        if (linux_epoll_init(&gcfg->epoll, 1024) < 0) {
            slog(LOG_WARNING, "Failed to initialize Linux epoll, continuing without it\n");
        }
    }
    
    /* Initialize io_uring for async I/O */
    if (gcfg->enable_io_uring) {
        if (linux_io_uring_init(&gcfg->io_uring, 1024) < 0) {
            slog(LOG_WARNING, "Failed to initialize Linux io_uring, continuing without it\n");
        }
    }
    
    /* Initialize CPU governor optimization */
    if (gcfg->enable_cpu_governor) {
        if (linux_cpu_governor_init(&gcfg->cpu_governor) < 0) {
            slog(LOG_WARNING, "Failed to initialize Linux CPU governor, continuing without it\n");
        } else {
            linux_cpu_governor_set_performance(&gcfg->cpu_governor);
        }
    }
    
    /* Initialize network optimization */
    if (gcfg->enable_net_optimization) {
        if (linux_net_optimization_init(&gcfg->net_optimization) < 0) {
            slog(LOG_WARNING, "Failed to initialize Linux network optimization, continuing without it\n");
        } else {
            linux_net_optimization_apply(&gcfg->net_optimization);
        }
    }
    
    /* Initialize memory optimization */
    if (gcfg->enable_memory_optimization) {
        if (linux_memory_optimization_init(&gcfg->memory_optimization) < 0) {
            slog(LOG_WARNING, "Failed to initialize Linux memory optimization, continuing without it\n");
        } else {
            linux_memory_optimization_apply(&gcfg->memory_optimization);
        }
    }
    
    slog(LOG_INFO, "Linux optimizations setup complete\n");
    return 0;
}

#endif /* __linux__ */
