/*
 * FreeBSD-specific optimizations for TAYGA
 * 
 * This file implements FreeBSD-specific performance optimizations including:
 * - Kqueue-based I/O multiplexing
 * - Async queue for background operations
 * - Packet buffer optimization
 * - Sysctl-based system tuning
 */

#ifdef __FreeBSD__

#include "tayga.h"
#include <sys/event.h>
#include <sys/sysctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>

/* Kqueue-based I/O multiplexing */
int freebsd_kqueue_init(struct freebsd_kqueue *kq, int max_events) {
    kq->kq_fd = kqueue();
    if (kq->kq_fd < 0) {
        slog(LOG_ERR, "Failed to create kqueue: %s\n", strerror(errno));
        return -1;
    }
    
    kq->max_events = max_events;
    kq->events = malloc(sizeof(struct kevent) * max_events);
    if (!kq->events) {
        close(kq->kq_fd);
        return -1;
    }
    
    slog(LOG_INFO, "FreeBSD kqueue initialized with %d max events\n", max_events);
    return 0;
}

void freebsd_kqueue_destroy(struct freebsd_kqueue *kq) {
    if (kq->kq_fd >= 0) {
        close(kq->kq_fd);
        kq->kq_fd = -1;
    }
    if (kq->events) {
        free(kq->events);
        kq->events = NULL;
    }
}

int freebsd_kqueue_add_fd(struct freebsd_kqueue *kq, int fd, int filter, int flags) {
    struct kevent kev;
    
    EV_SET(&kev, fd, filter, EV_ADD | flags, 0, 0, NULL);
    
    if (kevent(kq->kq_fd, &kev, 1, NULL, 0, NULL) < 0) {
        slog(LOG_ERR, "Failed to add fd %d to kqueue: %s\n", fd, strerror(errno));
        return -1;
    }
    
    return 0;
}

int freebsd_kqueue_wait(struct freebsd_kqueue *kq, struct kevent *events, int timeout_ms) {
    struct timespec timeout;
    int nfds;
    
    if (timeout_ms >= 0) {
        timeout.tv_sec = timeout_ms / 1000;
        timeout.tv_nsec = (timeout_ms % 1000) * 1000000;
    }
    
    nfds = kevent(kq->kq_fd, NULL, 0, events, kq->max_events, 
                  timeout_ms >= 0 ? &timeout : NULL);
    
    if (nfds < 0) {
        if (errno != EINTR) {
            slog(LOG_ERR, "kqueue wait failed: %s\n", strerror(errno));
        }
        return -1;
    }
    
    return nfds;
}

/* Async queue for background operations */
static void *freebsd_async_worker(void *arg) {
    struct freebsd_async_queue *aq = (struct freebsd_async_queue *)arg;
    
    while (1) {
        pthread_mutex_lock(&aq->queue_mutex);
        
        while (aq->queue_head == aq->queue_tail) {
            pthread_cond_wait(&aq->queue_cond, &aq->queue_mutex);
        }
        
        void *task = aq->task_queue[aq->queue_tail];
        aq->queue_tail = (aq->queue_tail + 1) % aq->queue_size;
        
        pthread_mutex_unlock(&aq->queue_mutex);
        
        /* Process the task */
        if (task) {
            /* Task processing logic would go here */
            slog(LOG_DEBUG, "FreeBSD async task processed\n");
        }
    }
    
    return NULL;
}

int freebsd_async_queue_init(struct freebsd_async_queue *aq, size_t queue_size) {
    aq->queue_size = queue_size;
    aq->queue_head = 0;
    aq->queue_tail = 0;
    
    aq->task_queue = malloc(sizeof(void *) * queue_size);
    if (!aq->task_queue) {
        slog(LOG_ERR, "Failed to allocate FreeBSD async queue\n");
        return -1;
    }
    
    if (pthread_mutex_init(&aq->queue_mutex, NULL) != 0) {
        free(aq->task_queue);
        slog(LOG_ERR, "Failed to initialize FreeBSD async queue mutex\n");
        return -1;
    }
    
    if (pthread_cond_init(&aq->queue_cond, NULL) != 0) {
        pthread_mutex_destroy(&aq->queue_mutex);
        free(aq->task_queue);
        slog(LOG_ERR, "Failed to initialize FreeBSD async queue condition\n");
        return -1;
    }
    
    if (pthread_create(&aq->worker_thread, NULL, freebsd_async_worker, aq) != 0) {
        pthread_cond_destroy(&aq->queue_cond);
        pthread_mutex_destroy(&aq->queue_mutex);
        free(aq->task_queue);
        slog(LOG_ERR, "Failed to create FreeBSD async worker thread\n");
        return -1;
    }
    
    slog(LOG_INFO, "FreeBSD async queue initialized with %zu slots\n", queue_size);
    return 0;
}

void freebsd_async_queue_destroy(struct freebsd_async_queue *aq) {
    if (aq->worker_thread) {
        pthread_cancel(aq->worker_thread);
        pthread_join(aq->worker_thread, NULL);
    }
    
    if (aq->task_queue) {
        free(aq->task_queue);
        aq->task_queue = NULL;
    }
    
    pthread_cond_destroy(&aq->queue_cond);
    pthread_mutex_destroy(&aq->queue_mutex);
}

int freebsd_async_queue_enqueue(struct freebsd_async_queue *aq, void *task) {
    pthread_mutex_lock(&aq->queue_mutex);
    
    size_t next_head = (aq->queue_head + 1) % aq->queue_size;
    if (next_head == aq->queue_tail) {
        pthread_mutex_unlock(&aq->queue_mutex);
        return -1; /* Queue full */
    }
    
    aq->task_queue[aq->queue_head] = task;
    aq->queue_head = next_head;
    
    pthread_cond_signal(&aq->queue_cond);
    pthread_mutex_unlock(&aq->queue_mutex);
    
    return 0;
}

/* Packet buffer optimization */
int freebsd_packet_pool_init(struct freebsd_packet_pool *pool, size_t pool_size, size_t buffer_size) {
    pool->pool_size = pool_size;
    pool->buffer_size = buffer_size;
    pool->used_count = 0;
    
    pool->packet_buffers = malloc(sizeof(uint8_t *) * pool_size);
    if (!pool->packet_buffers) {
        slog(LOG_ERR, "Failed to allocate FreeBSD packet pool\n");
        return -1;
    }
    
    /* Allocate packet buffers */
    for (size_t i = 0; i < pool_size; i++) {
        pool->packet_buffers[i] = malloc(buffer_size);
        if (!pool->packet_buffers[i]) {
            /* Clean up previously allocated buffers */
            for (size_t j = 0; j < i; j++) {
                free(pool->packet_buffers[j]);
            }
            free(pool->packet_buffers);
            slog(LOG_ERR, "Failed to allocate FreeBSD packet buffer %zu\n", i);
            return -1;
        }
    }
    
    slog(LOG_INFO, "FreeBSD packet pool initialized with %zu buffers of %zu bytes\n", 
         pool_size, buffer_size);
    return 0;
}

void freebsd_packet_pool_destroy(struct freebsd_packet_pool *pool) {
    if (pool->packet_buffers) {
        for (size_t i = 0; i < pool->pool_size; i++) {
            if (pool->packet_buffers[i]) {
                free(pool->packet_buffers[i]);
            }
        }
        free(pool->packet_buffers);
        pool->packet_buffers = NULL;
    }
}

uint8_t *freebsd_packet_pool_alloc(struct freebsd_packet_pool *pool) {
    if (pool->used_count >= pool->pool_size) {
        return NULL; /* Pool exhausted */
    }
    
    uint8_t *buffer = pool->packet_buffers[pool->used_count];
    pool->used_count++;
    
    return buffer;
}

void freebsd_packet_pool_free(struct freebsd_packet_pool *pool, uint8_t *buffer) {
    if (buffer && pool->used_count > 0) {
        pool->used_count--;
        /* Buffer is ready for reuse */
    }
}

/* Sysctl-based system tuning */
int freebsd_sysctl_tuning_init(struct freebsd_sysctl_tuning *tuning) {
    size_t len;
    
    /* Get current values */
    len = sizeof(tuning->tcp_sendspace);
    if (sysctlbyname("net.inet.tcp.sendspace", &tuning->tcp_sendspace, &len, NULL, 0) < 0) {
        slog(LOG_WARNING, "Failed to get tcp.sendspace: %s\n", strerror(errno));
        tuning->tcp_sendspace = 32768; /* Default */
    }
    
    len = sizeof(tuning->tcp_recvspace);
    if (sysctlbyname("net.inet.tcp.recvspace", &tuning->tcp_recvspace, &len, NULL, 0) < 0) {
        slog(LOG_WARNING, "Failed to get tcp.recvspace: %s\n", strerror(errno));
        tuning->tcp_recvspace = 65536; /* Default */
    }
    
    len = sizeof(tuning->maxfiles);
    if (sysctlbyname("kern.maxfiles", &tuning->maxfiles, &len, NULL, 0) < 0) {
        slog(LOG_WARNING, "Failed to get maxfiles: %s\n", strerror(errno));
        tuning->maxfiles = 63469; /* Default */
    }
    
    len = sizeof(tuning->maxfilesperproc);
    if (sysctlbyname("kern.maxfilesperproc", &tuning->maxfilesperproc, &len, NULL, 0) < 0) {
        slog(LOG_WARNING, "Failed to get maxfilesperproc: %s\n", strerror(errno));
        tuning->maxfilesperproc = 57114; /* Default */
    }
    
    slog(LOG_INFO, "FreeBSD sysctl tuning initialized\n");
    return 0;
}

void freebsd_sysctl_tuning_apply(struct freebsd_sysctl_tuning *tuning) {
    /* Optimize TCP buffers for high throughput */
    int new_sendspace = 131072;  /* 128KB */
    int new_recvspace = 262144;  /* 256KB */
    
    if (sysctlbyname("net.inet.tcp.sendspace", NULL, NULL, &new_sendspace, sizeof(new_sendspace)) < 0) {
        slog(LOG_WARNING, "Failed to set tcp.sendspace: %s\n", strerror(errno));
    } else {
        slog(LOG_INFO, "Set tcp.sendspace to %d\n", new_sendspace);
    }
    
    if (sysctlbyname("net.inet.tcp.recvspace", NULL, NULL, &new_recvspace, sizeof(new_recvspace)) < 0) {
        slog(LOG_WARNING, "Failed to set tcp.recvspace: %s\n", strerror(errno));
    } else {
        slog(LOG_INFO, "Set tcp.recvspace to %d\n", new_recvspace);
    }
    
    /* Increase file descriptor limits */
    int new_maxfiles = 100000;
    int new_maxfilesperproc = 90000;
    
    if (sysctlbyname("kern.maxfiles", NULL, NULL, &new_maxfiles, sizeof(new_maxfiles)) < 0) {
        slog(LOG_WARNING, "Failed to set maxfiles: %s\n", strerror(errno));
    } else {
        slog(LOG_INFO, "Set maxfiles to %d\n", new_maxfiles);
    }
    
    if (sysctlbyname("kern.maxfilesperproc", NULL, NULL, &new_maxfilesperproc, sizeof(new_maxfilesperproc)) < 0) {
        slog(LOG_WARNING, "Failed to set maxfilesperproc: %s\n", strerror(errno));
    } else {
        slog(LOG_INFO, "Set maxfilesperproc to %d\n", new_maxfilesperproc);
    }
}

void freebsd_sysctl_tuning_restore(struct freebsd_sysctl_tuning *tuning) {
    /* Restore original values */
    sysctlbyname("net.inet.tcp.sendspace", NULL, NULL, &tuning->tcp_sendspace, sizeof(tuning->tcp_sendspace));
    sysctlbyname("net.inet.tcp.recvspace", NULL, NULL, &tuning->tcp_recvspace, sizeof(tuning->tcp_recvspace));
    sysctlbyname("kern.maxfiles", NULL, NULL, &tuning->maxfiles, sizeof(tuning->maxfiles));
    sysctlbyname("kern.maxfilesperproc", NULL, NULL, &tuning->maxfilesperproc, sizeof(tuning->maxfilesperproc));
    
    slog(LOG_INFO, "FreeBSD sysctl tuning restored to original values\n");
}

/* Main FreeBSD optimization setup function */
int setup_freebsd_optimizations(void) {
    slog(LOG_INFO, "Setting up FreeBSD-specific optimizations\n");
    
    /* Initialize kqueue for I/O multiplexing */
    if (gcfg->enable_kqueue_io) {
        if (freebsd_kqueue_init(&gcfg->kqueue, 1024) < 0) {
            slog(LOG_WARNING, "Failed to initialize FreeBSD kqueue, continuing without it\n");
        }
    }
    
    /* Initialize async queue for background operations */
    if (gcfg->enable_async_queue) {
        if (freebsd_async_queue_init(&gcfg->async_queue, 1000) < 0) {
            slog(LOG_WARNING, "Failed to initialize FreeBSD async queue, continuing without it\n");
        }
    }
    
    /* Initialize packet pool for buffer optimization */
    if (gcfg->enable_packet_optimization) {
        if (freebsd_packet_pool_init(&gcfg->packet_pool, 1000, 65536) < 0) {
            slog(LOG_WARNING, "Failed to initialize FreeBSD packet pool, continuing without it\n");
        }
    }
    
    /* Initialize and apply sysctl tuning */
    if (gcfg->enable_sysctl_tuning) {
        if (freebsd_sysctl_tuning_init(&gcfg->sysctl_tuning) < 0) {
            slog(LOG_WARNING, "Failed to initialize FreeBSD sysctl tuning, continuing without it\n");
        } else {
            freebsd_sysctl_tuning_apply(&gcfg->sysctl_tuning);
        }
    }
    
    slog(LOG_INFO, "FreeBSD optimizations setup complete\n");
    return 0;
}

#endif /* __FreeBSD__ */