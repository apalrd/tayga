/*
 *  threading.c -- multi-threading support for TAYGA
 *
 *  part of TAYGA <https://github.com/apalrd/tayga>
 *  Copyright (C) 2010  Nathan Lutchansky <lutchann@litech.org>
 *  Copyright (C) 2025  Andrew Palardy <andrew@apalrd.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 */

#include "tayga.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

/* Get optimal number of worker threads based on CPU cores */
int get_optimal_thread_count(int configured_threads)
{
	int cpu_cores;
	
	if (configured_threads > 0) {
		/* User explicitly configured thread count */
		return configured_threads;
	}
	
	/* Auto-detect CPU cores */
	cpu_cores = sysconf(_SC_NPROCESSORS_ONLN);
	if (cpu_cores <= 0) {
		/* Fallback if detection fails */
		cpu_cores = 4;
		slog(LOG_WARNING, "Unable to detect CPU cores, defaulting to %d\n", cpu_cores);
	} else {
		slog(LOG_INFO, "Detected %d CPU cores\n", cpu_cores);
	}
	
	/* For packet processing, we typically want:
	 * - At least 2 threads for basic parallelism
	 * - Up to CPU cores for optimal utilization
	 * - Cap at 16 threads to avoid excessive context switching
	 */
	if (cpu_cores < 2) {
		return 2;
	} else if (cpu_cores > 16) {
		return 16;
	} else {
		return cpu_cores;
	}
}

/* Initialize thread pool */
int thread_pool_init(struct thread_pool *pool, int num_threads)
{
	int i, ret;

	if (num_threads <= 0) {
		slog(LOG_ERR, "Invalid number of threads: %d\n", num_threads);
		return -1;
	}

	pool->threads = malloc(num_threads * sizeof(pthread_t));
	if (!pool->threads) {
		slog(LOG_CRIT, "Failed to allocate memory for thread pool\n");
		return -1;
	}

	pool->num_threads = num_threads;
	atomic_init(&pool->shutdown, 0);
	atomic_init(&pool->active_workers, 0);

	/* Create worker threads with optimizations */
	for (i = 0; i < num_threads; i++) {
		ret = pthread_create(&pool->threads[i], NULL, worker_thread, pool);
		if (ret != 0) {
			slog(LOG_CRIT, "Failed to create worker thread %d: %s\n", 
				i, strerror(ret));
			/* Clean up already created threads */
			atomic_store(&pool->shutdown, 1);
			for (int j = 0; j < i; j++) {
				pthread_join(pool->threads[j], NULL);
			}
			free(pool->threads);
			pool->threads = NULL;
			return -1;
		}
		
		/* Setup NUMA affinity if enabled */
		if (gcfg->enable_numa_optimization) {
			setup_numa_affinity(i, num_threads);
		}
		
		/* Setup CPU affinity for better cache performance */
		setup_cpu_affinity(pool->threads[i], i);
	}

	slog(LOG_INFO, "Created thread pool with %d worker threads\n", num_threads);
	return 0;
}

/* Destroy thread pool */
void thread_pool_destroy(struct thread_pool *pool)
{
	int i;

	if (!pool->threads) {
		return;
	}

	/* Signal shutdown to all threads */
	atomic_store(&pool->shutdown, 1);

	/* Wake up all waiting threads */
	pthread_cond_broadcast(&gcfg->packet_queue.cond);

	/* Wait for all threads to finish */
	for (i = 0; i < pool->num_threads; i++) {
		pthread_join(pool->threads[i], NULL);
	}

	free(pool->threads);
	pool->threads = NULL;
	pool->num_threads = 0;

	slog(LOG_INFO, "Thread pool destroyed\n");
}

/* Initialize lock-free packet queue */
int packet_queue_init(struct packet_queue *queue, size_t size)
{
	if (size == 0) {
		slog(LOG_ERR, "Invalid queue size: %zu\n", size);
		return -1;
	}

	/* Ensure size is power of 2 for efficient modulo operations */
	if (size & (size - 1)) {
		/* Round up to next power of 2 */
		size_t new_size = 1;
		while (new_size < size) {
			new_size <<= 1;
		}
		size = new_size;
		slog(LOG_INFO, "Adjusted queue size to power of 2: %zu\n", size);
	}

	queue->packets = malloc(size * sizeof(struct thread_pkt));
	if (!queue->packets) {
		slog(LOG_CRIT, "Failed to allocate memory for packet queue\n");
		return -1;
	}

	queue->size = size;
	atomic_init(&queue->head, 0);
	atomic_init(&queue->tail, 0);
	atomic_init(&queue->count, 0);

	/* Only initialize condition variable mutex, not queue access mutex */
	if (pthread_mutex_init(&queue->cond_mutex, NULL) != 0) {
		slog(LOG_CRIT, "Failed to initialize queue condition mutex\n");
		free(queue->packets);
		return -1;
	}

	if (pthread_cond_init(&queue->cond, NULL) != 0) {
		slog(LOG_CRIT, "Failed to initialize queue condition variable\n");
		pthread_mutex_destroy(&queue->cond_mutex);
		free(queue->packets);
		return -1;
	}

	slog(LOG_INFO, "Initialized lock-free packet queue with size %zu\n", size);
	return 0;
}

/* Destroy packet queue */
void packet_queue_destroy(struct packet_queue *queue)
{
	if (queue->packets) {
		free(queue->packets);
		queue->packets = NULL;
	}
	pthread_cond_destroy(&queue->cond);
	pthread_mutex_destroy(&queue->cond_mutex);
}

/* Lock-free enqueue packet for processing */
int packet_queue_enqueue(struct packet_queue *queue, const struct thread_pkt *pkt)
{
	size_t head, tail, next_head;
	size_t size_mask = queue->size - 1;  // Since size is power of 2

	while (1) {
		head = atomic_load(&queue->head);
		tail = atomic_load(&queue->tail);
		next_head = (head + 1) & size_mask;

		/* Check if queue is full */
		if (next_head == tail) {
			slog(LOG_WARNING, "Packet queue is full, dropping packet\n");
			return -1;
		}

		/* Try to claim the slot */
		if (atomic_compare_exchange_weak(&queue->head, &head, next_head)) {
			/* Successfully claimed the slot, copy packet data */
			queue->packets[head] = *pkt;
			
			/* Update count atomically */
			atomic_fetch_add(&queue->count, 1);
			
			/* Signal waiting threads */
			pthread_mutex_lock(&queue->cond_mutex);
			pthread_cond_signal(&queue->cond);
			pthread_mutex_unlock(&queue->cond_mutex);
			
			return 0;
		}
		/* CAS failed, retry */
	}
}

/* Lock-free dequeue packet for processing */
int packet_queue_dequeue(struct packet_queue *queue, struct thread_pkt *pkt)
{
	size_t head, tail, next_tail;
	size_t size_mask = queue->size - 1;  // Since size is power of 2

	while (1) {
		head = atomic_load(&queue->head);
		tail = atomic_load(&queue->tail);

		/* Check if queue is empty */
		if (head == tail) {
			/* Check if we should shutdown */
			if (atomic_load(&gcfg->thread_pool.shutdown)) {
				return -1; /* Shutdown signal */
			}

			/* Wait for packets using condition variable */
			pthread_mutex_lock(&queue->cond_mutex);
			if (atomic_load(&queue->head) == atomic_load(&queue->tail)) {
				pthread_cond_wait(&queue->cond, &queue->cond_mutex);
			}
			pthread_mutex_unlock(&queue->cond_mutex);
			continue;
		}

		/* Try to claim the slot */
		next_tail = (tail + 1) & size_mask;
		if (atomic_compare_exchange_weak(&queue->tail, &tail, next_tail)) {
			/* Successfully claimed the slot, copy packet data */
			*pkt = queue->packets[tail];
			
			/* Update count atomically */
			atomic_fetch_sub(&queue->count, 1);
			
			return 0;
		}
		/* CAS failed, retry */
	}
}

/* Lock-free batch dequeue for processing multiple packets at once */
int packet_queue_dequeue_batch(struct packet_queue *queue, struct packet_batch *batch)
{
	size_t head, tail, available, to_dequeue;
	size_t size_mask = queue->size - 1;
	size_t max_batch = sizeof(batch->packets) / sizeof(batch->packets[0]);
	
	batch->count = 0;

	while (1) {
		head = atomic_load(&queue->head);
		tail = atomic_load(&queue->tail);

		/* Check if queue is empty */
		if (head == tail) {
			/* Check if we should shutdown */
			if (atomic_load(&gcfg->thread_pool.shutdown)) {
				return -1; /* Shutdown signal */
			}

			/* Wait for packets using condition variable */
			pthread_mutex_lock(&queue->cond_mutex);
			if (atomic_load(&queue->head) == atomic_load(&queue->tail)) {
				pthread_cond_wait(&queue->cond, &queue->cond_mutex);
			}
			pthread_mutex_unlock(&queue->cond_mutex);
			continue;
		}

		/* Calculate how many packets we can dequeue */
		available = (head - tail) & size_mask;
		to_dequeue = (available > max_batch) ? max_batch : available;

		/* Try to claim multiple slots */
		size_t new_tail = (tail + to_dequeue) & size_mask;
		if (atomic_compare_exchange_weak(&queue->tail, &tail, new_tail)) {
			/* Successfully claimed slots, copy packet data */
			for (size_t i = 0; i < to_dequeue; i++) {
				size_t slot = (tail + i) & size_mask;
				batch->packets[i] = queue->packets[slot];
			}
			batch->count = to_dequeue;
			
			/* Update count atomically */
			atomic_fetch_sub(&queue->count, to_dequeue);
			
			return 0;
		}
		/* CAS failed, retry */
	}
}

/* Worker thread function with batch processing support */
void *worker_thread(void *arg)
{
	struct thread_pool *pool = (struct thread_pool *)arg;
	struct thread_pkt thread_pkt;
	struct packet_batch batch;
	int ret;

	atomic_fetch_add(&pool->active_workers, 1);

	slog(LOG_DEBUG, "Worker thread started\n");

	while (!atomic_load(&pool->shutdown)) {
		/* Try batch processing first if enabled */
		if (gcfg->enable_batch_processing) {
			ret = packet_queue_dequeue_batch(&gcfg->packet_queue, &batch);
			if (ret < 0) {
				/* Shutdown signal or error */
				break;
			}
			
			if (batch.count > 0) {
				/* Process batch of packets */
				process_packet_batch(&batch);
				
				/* Free all packet data in batch */
				for (size_t i = 0; i < batch.count; i++) {
					if (batch.packets[i].data_copy) {
						packet_mem_pool_free(&gcfg->mem_pool, batch.packets[i].data_copy);
					}
				}
				continue;
			}
		}
		
		/* Fall back to single packet processing */
		ret = packet_queue_dequeue(&gcfg->packet_queue, &thread_pkt);
		if (ret < 0) {
			/* Shutdown signal or error */
			break;
		}

		/* Process the packet */
		process_packet_threaded(&thread_pkt);

		/* Free the copied packet data */
		if (thread_pkt.data_copy) {
			packet_mem_pool_free(&gcfg->mem_pool, thread_pkt.data_copy);
		}
	}

	atomic_fetch_sub(&pool->active_workers, 1);
	slog(LOG_DEBUG, "Worker thread exiting\n");

	return NULL;
}

/* Process packet in worker thread */
int process_packet_threaded(const struct thread_pkt *thread_pkt)
{
	struct pkt pkt = thread_pkt->pkt;

	/* Set up packet data pointer to point to our copy */
	pkt.data = thread_pkt->data_copy;

	/* Process based on protocol */
	switch (TUN_GET_PROTO(&thread_pkt->pi)) {
	case ETH_P_IP:
		handle_ip4(&pkt);
		break;
	case ETH_P_IPV6:
		handle_ip6(&pkt);
		break;
	default:
		slog(LOG_WARNING, "Dropping unknown proto %04x from "
				"tun device\n", ntohs(thread_pkt->pi.proto));
		break;
	}

	return 0;
}

/* Process batch of packets in worker thread */
int process_packet_batch(const struct packet_batch *batch)
{
	for (size_t i = 0; i < batch->count; i++) {
		process_packet_threaded(&batch->packets[i]);
	}
	return 0;
}

/* Initialize packet memory pool */
int packet_mem_pool_init(struct packet_mem_pool *pool, size_t pool_size, size_t chunk_size)
{
	if (pool_size == 0 || chunk_size == 0) {
		slog(LOG_ERR, "Invalid memory pool parameters: pool_size=%zu, chunk_size=%zu\n", 
			pool_size, chunk_size);
		return -1;
	}

	pool->pool = malloc(pool_size);
	if (!pool->pool) {
		slog(LOG_CRIT, "Failed to allocate memory pool of size %zu\n", pool_size);
		return -1;
	}

	pool->pool_size = pool_size;
	pool->chunk_size = chunk_size;
	atomic_init(&pool->next_free, 0);

	if (pthread_mutex_init(&pool->mutex, NULL) != 0) {
		slog(LOG_CRIT, "Failed to initialize memory pool mutex\n");
		free(pool->pool);
		return -1;
	}

	slog(LOG_INFO, "Initialized packet memory pool: %zu bytes, %zu byte chunks\n", 
		pool_size, chunk_size);
	return 0;
}

/* Destroy packet memory pool */
void packet_mem_pool_destroy(struct packet_mem_pool *pool)
{
	if (pool->pool) {
		free(pool->pool);
		pool->pool = NULL;
	}
	pthread_mutex_destroy(&pool->mutex);
}

/* Allocate memory from pool */
uint8_t *packet_mem_pool_alloc(struct packet_mem_pool *pool, size_t size)
{
	size_t offset, chunks_needed;

	if (size > pool->chunk_size) {
		/* Fall back to malloc for oversized requests */
		return malloc(size);
	}

	chunks_needed = (size + pool->chunk_size - 1) / pool->chunk_size;

	pthread_mutex_lock(&pool->mutex);

	offset = atomic_load(&pool->next_free);
	if (offset + (chunks_needed * pool->chunk_size) > pool->pool_size) {
		/* Pool exhausted, fall back to malloc */
		pthread_mutex_unlock(&pool->mutex);
		return malloc(size);
	}

	atomic_store(&pool->next_free, offset + (chunks_needed * pool->chunk_size));
	pthread_mutex_unlock(&pool->mutex);

	return pool->pool + offset;
}

/* Free memory back to pool (no-op for pool allocations) */
void packet_mem_pool_free(struct packet_mem_pool *pool, uint8_t *ptr)
{
	/* For simplicity, we don't implement free for pool allocations */
	/* In a production system, you'd want to implement proper free tracking */
	(void)pool;
	(void)ptr;
}

/* NUMA and CPU affinity functions */

/* Setup NUMA affinity for thread */
int setup_numa_affinity(int thread_id, int num_threads)
{
#ifdef __linux__
	int numa_nodes = numa_available();
	if (numa_nodes <= 0) {
		slog(LOG_INFO, "NUMA not available, skipping NUMA optimization\n");
		return 0;
	}
	
	/* Calculate which NUMA node this thread should use */
	int numa_node = thread_id % numa_nodes;
	
	/* Set NUMA policy for this thread */
	if (numa_run_on_node(numa_node) < 0) {
		slog(LOG_WARNING, "Failed to set NUMA node %d for thread %d: %s\n", 
			numa_node, thread_id, strerror(errno));
		return -1;
	}
	
	/* Allocate memory on the preferred NUMA node */
	if (numa_alloc_onnode(4096, numa_node) == NULL) {
		slog(LOG_WARNING, "Failed to allocate memory on NUMA node %d\n", numa_node);
	}
	
	slog(LOG_DEBUG, "Thread %d assigned to NUMA node %d\n", thread_id, numa_node);
	return 0;
#else
	(void)thread_id;
	(void)num_threads;
	slog(LOG_INFO, "NUMA optimization not supported on this platform\n");
	return 0;
#endif
}

/* Setup CPU affinity for thread */
int setup_cpu_affinity(pthread_t thread, int cpu_id)
{
#ifdef __linux__
	cpu_set_t cpuset;
	CPU_ZERO(&cpuset);
	CPU_SET(cpu_id, &cpuset);
	
	if (pthread_setaffinity_np(thread, sizeof(cpuset), &cpuset) != 0) {
		slog(LOG_WARNING, "Failed to set CPU affinity for thread: %s\n", strerror(errno));
		return -1;
	}
	
	slog(LOG_DEBUG, "Thread pinned to CPU %d\n", cpu_id);
	return 0;
#elif defined(__APPLE__)
	/* macOS CPU affinity implementation */
	thread_affinity_policy_data_t affinity_policy;
	affinity_policy.affinity_tag = cpu_id;
	
	kern_return_t result = thread_policy_set(pthread_mach_thread_np(thread),
		THREAD_AFFINITY_POLICY, (thread_policy_t)&affinity_policy,
		THREAD_AFFINITY_POLICY_COUNT);
	
	if (result != KERN_SUCCESS) {
		slog(LOG_WARNING, "Failed to set CPU affinity for thread on macOS\n");
		return -1;
	}
	
	slog(LOG_DEBUG, "Thread pinned to CPU %d (macOS)\n", cpu_id);
	return 0;
#else
	(void)thread;
	(void)cpu_id;
	slog(LOG_INFO, "CPU affinity not supported on this platform\n");
	return 0;
#endif
}

/* Vectorized checksum calculation using SIMD */
uint32_t calculate_checksum_vectorized(const uint8_t *data, size_t len)
{
	uint32_t sum = 0;
	size_t i;
	
	/* Process 4 bytes at a time for better performance */
	for (i = 0; i < len - 3; i += 4) {
		uint32_t word = *(uint32_t*)(data + i);
		sum += (word >> 16) + (word & 0xFFFF);
	}
	
	/* Handle remaining bytes */
	for (; i < len; i++) {
		sum += data[i];
	}
	
	/* Fold carry bits */
	while (sum >> 16) {
		sum = (sum & 0xFFFF) + (sum >> 16);
	}
	
	return ~sum;
}

/* Zero-copy packet initialization */
int zero_copy_packet_init(struct zero_copy_pkt *pkt, uint8_t *buffer, size_t offset, size_t len)
{
	if (!pkt || !buffer) {
		return -1;
	}
	
	pkt->direct_buffer = buffer;
	pkt->offset = offset;
	pkt->length = len;
	
	return 0;
}
