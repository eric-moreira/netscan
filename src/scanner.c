#define _GNU_SOURCE
#include <stddef.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/select.h>
#include <netdb.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include "../include/scanner.h"

#define true 1
#define false 0


int scan_port(char *host, int port, int seconds)
{	
    // Port 0 is reserved and invalid for scanning
    if(port <= 0 || port > 65535){
        fprintf(stderr,"Invalid port \n");
        return -1;
    }
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	fcntl(sock, F_SETFL, O_NONBLOCK);
	struct addrinfo hints, *result;

	memset(&hints, 0, sizeof(hints));

	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	if (getaddrinfo(host, NULL, &hints, &result) != 0) {
		fprintf(stderr, "getaddrinfo() failed\n");
		return -1;
	}

	struct sockaddr_in *addr_in = (struct sockaddr_in *)result->ai_addr;

	addr_in->sin_port = htons(port);	// LEndian 0x0050 p/ BEndian 0x5000

	int res = connect(sock, (struct sockaddr *)addr_in, sizeof(*addr_in));

	if (res == -1 && errno != EINPROGRESS) {
		fprintf(stderr, "error in connect() %d\n", errno);
		return -1;
	}

	fd_set socket_fds;
	FD_ZERO(&socket_fds);
	FD_SET(sock, &socket_fds);

	struct timeval timeout;
	timeout.tv_sec = 3;
	timeout.tv_usec = 0;
	if (seconds > 0) {
		timeout.tv_sec = seconds;
		timeout.tv_usec = 0;
	}

	int num_ready_sockets =
		select(sock + 1, NULL, &socket_fds, NULL, &timeout);

	if (num_ready_sockets <= 0) {
		return PORT_CLOSED;  // Timeout or error - port is closed
	}

	int error = 0;
	socklen_t len = sizeof(error);

	if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &len) == 0) {
		if (error == 0) {
			freeaddrinfo(result);
			close(sock);
			return PORT_OPEN;  // Port is open
		} else {
			freeaddrinfo(result);
			close(sock);
			return PORT_CLOSED;  // Port is closed
		}
	}

	freeaddrinfo(result);
	close(sock);
	return PORT_CLOSED;  // Default to closed if we can't determine
}


int* parse_single_port(char* str, int*  count){
	int port = atoi(str);
	if(port <= 0 || port > 65535) return NULL;

	int* ports = malloc(sizeof(int));
	ports[0] = port;
	*count = 1;
	return ports;
}

int* parse_port_range(char* str, int* count){
	char strstart[64];
	strcpy(strstart, str);
	char* dash = strchr(strstart, '-');
	*dash = '\0';
	int start = atoi(strstart);
	int end = atoi(dash+1);
	if(start < 0 || end > 65535 || start > end) return NULL;
	*count = end - start + 1;
	int *ports = malloc(*count * sizeof(int));
	for (int i =0; i< *count; i++){
		ports[i] = start + i;
	}
	return ports;
}

int* parse_port_list(char* str, int* count){
	char buffer[1024];
	strncpy(buffer, str, sizeof(buffer)-1);
	buffer[sizeof(buffer)-1] = '\0';
	
	int *all_ports = NULL;
	int total_count = 0;
	
	char *token = strtok(buffer, ",");
	while (token){
		int *current_ports;
		int current_count;

		if(strchr(token, '-')){
			current_ports = parse_port_range(token, &current_count);
		} else {
			current_ports = parse_single_port(token, &current_count);
		}

		if(current_ports) {
			all_ports = realloc(all_ports, (total_count + current_count) * sizeof(int));
			for(int i =0; i < current_count; i++){
				all_ports[total_count + i] = current_ports[i];
			}
			total_count += current_count;
			free(current_ports);
		}

		token = strtok(NULL, ",");
	}
	*count = total_count;
	return all_ports;
}

int resolve_hostname(const char* hostname, char* ip_buffer){
	struct addrinfo hints, *result;
	memset(&hints, 0, sizeof(hints));

	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	if(getaddrinfo(hostname, NULL, &hints, &result) != 0){
		fprintf(stderr, "Could not resolve host: %s", hostname);
		return -1;
	}

	struct sockaddr_in *addr_in = (struct sockaddr_in*)result->ai_addr;

	inet_ntop(AF_INET, &(addr_in->sin_addr), ip_buffer, INET_ADDRSTRLEN);

	freeaddrinfo(result);
	return 0;
}

int threaded_scan_ports(scan_config_t *config, scan_result_t **results) {
    if(!config || !results || config->thread_count <= 0 || !config->ports) {
        return -1;
    }

    work_queue_t *work_queue = malloc(sizeof(work_queue_t));
    if(!work_queue) {
        return -1;
    }

    *results = malloc(config->port_count * sizeof(scan_result_t));
    if(!*results) {
        free(work_queue);
        return -1;
    }

    work_queue->config = config;
    work_queue->results = *results;
    work_queue->current_index = 0;
	work_queue->completed_count = 0;

    if(pthread_mutex_init(&work_queue->mutex, NULL) != 0) {
        free(*results);
        free(work_queue);
        return -1;
    }

    pthread_t threads[config->thread_count];
    int threads_created = 0;

    for(int i = 0; i < config->thread_count; i++) {
        if(pthread_create(&threads[i], NULL, worker_thread, work_queue) != 0) {
            break;
        }
        threads_created++;
    }

    if(threads_created == 0) {
        pthread_mutex_destroy(&work_queue->mutex);
        free(*results);
        free(work_queue);
        return -1;
    }

    for(int i = 0; i < threads_created; i++) {
        pthread_join(threads[i], NULL);
    }

    pthread_mutex_destroy(&work_queue->mutex);
    free(work_queue);

    return 0;
}

void* worker_thread(void *arg){
	work_queue_t *work_queue = (work_queue_t*) arg;
 	while(true){
		work_item_t item;
		if(get_next_port(work_queue, &item) == -1){
			break;
		}
		int status;
		if(work_queue->config->protocol == P_UDP){
			char default_payload[] = "test";
			status = scan_udp_port(work_queue->config->host, item.port,
				 work_queue->config->timeout, default_payload, 
				 strlen(default_payload));
		} else {
			status = scan_port(work_queue->config->host, item.port,
			 work_queue->config->timeout);
		}
		
		save_result(work_queue, &item, status);

		mark_port_completed(work_queue);
	}
	return NULL;
}

int get_next_port(work_queue_t *work_queue, work_item_t *item){
	pthread_mutex_lock(&work_queue->mutex);

	if (work_queue->current_index >= work_queue->config->port_count){
		pthread_mutex_unlock(&work_queue->mutex);
		return -1;
	}

	item->port = work_queue->config->ports[work_queue->current_index];
	item->index = work_queue->current_index;
	work_queue->current_index++;

	pthread_mutex_unlock(&work_queue->mutex);
	return 0;
}

void save_result(work_queue_t *work_queue, work_item_t *item, int status){
	work_queue->results[item->index].port = item->port;
	work_queue->results[item->index].status = status;	
}

pthread_mutex_t progress_mutex = PTHREAD_MUTEX_INITIALIZER;
void update_progress(int completed, int total){
	int bar_width = 50;
	float percentage = (float)completed/total;
	int filled = (int)(percentage*bar_width);
	
	pthread_mutex_lock(&progress_mutex);
	printf("\rProgress: [");
	for(int i=0; i<filled;i++){
		printf("█");
	}
	for(int i=filled; i<bar_width; i++){
		printf("░");
	}

	printf("] %.1f%% (%d/%d)", percentage*100, completed, total);
	fflush(stdout);

	if(completed==total){
		printf("\n");
	}
	pthread_mutex_unlock(&progress_mutex);
}

void mark_port_completed(work_queue_t *work_queue){
	pthread_mutex_lock(&work_queue->mutex);

	work_queue->completed_count++;
	int completed = work_queue->completed_count;
	int total = work_queue->config->port_count;

	pthread_mutex_unlock(&work_queue->mutex);

	update_progress(completed, total);
}

int scan_udp_port(char *host, int port, int timeout, char *payload, int payload_len){
	if(port <= 0 || port > 65535){
		fprintf(stderr, "Invalid port \n");
		return -1;
	}

	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	fcntl(sock, F_SETFL, O_NONBLOCK);
	struct addrinfo hints, *result;

	memset(&hints, 0, sizeof(hints));

	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;

	if (getaddrinfo(host, NULL, &hints, &result) != 0) {
		fprintf(stderr, "getaddrinfo() failed\n");
		return -1;
	}

	struct sockaddr_in *addr_in = (struct sockaddr_in *)result->ai_addr;

	addr_in->sin_port = htons(port);

	if(sendto(sock, payload, payload_len, 0, addr_in, sizeof(*addr_in))<0){
		perror("sendto");
		freeaddrinfo(result);
		close(sock);
		return -1;
	}

	fd_set read_fds;
	FD_ZERO(&read_fds);
	FD_SET(sock, &read_fds);


	struct timeval tv;
	tv.tv_sec = timeout > 0 ? timeout : 3;
	tv.tv_usec = 0;

	int select_result = select(sock+1, & read_fds, NULL, NULL, &tv);

	int status;

	if(select_result > 0){
		char buf[1024];
		ssize_t bytes = recvfrom(sock, buf, sizeof(buf), 0, NULL, NULL);
		if (bytes > 0){
			status = UDP_PORT_OPEN;
		} else {
			status = UDP_PORT_FILTERED;
		}
	} else if(select_result == 0) {
		status = UDP_PORT_FILTERED;
	} else {
		perror("select");
		status = -1;
	}
	
	freeaddrinfo(result);
	close(sock);
	return status;
}

const char* get_port_status_string(int status, protocol_t protocol){
	if(protocol == P_UDP){
		switch (status) {
              case UDP_PORT_OPEN: return "open";
              case UDP_PORT_FILTERED: return "filtered";
              case UDP_PORT_CLOSED: return "closed";
              default: return "unknown";
          }
	} else {
		return status == PORT_OPEN ? "open" : "closed";
	}
}