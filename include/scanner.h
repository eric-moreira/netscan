#ifndef SCANNER_H
#define SCANNER_H

#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

typedef struct {
    char *host;
    int *ports;
    int port_count;
    int thread_count;
    int timeout;
} scan_config_t;

typedef struct {
    int port;
    int status;
    char service[32];
} scan_result_t;

typedef struct {
    int *ports;
    int total_ports;
    int current_index;
    pthread_mutex_t mutex;
    scan_config_t *config;
    scan_result_t *results;
} work_queue_t;

int scan_port(char *host, int port, int seconds);
int* parse_single_port(char* str, int* count);
int* parse_port_range(char* str, int* count);
int* parse_port_list(char* str, int* count);
int resolve_hostname(const char* hostname, char* ip_buffer);

int threaded_scan_ports(scan_config_t *config, scan_result_t **results);

void* worker_thread(void* arg);



#endif