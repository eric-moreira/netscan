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
    int current_index;
    int completed_count;
    pthread_mutex_t mutex;
    scan_config_t *config;
    scan_result_t *results;
} work_queue_t;

typedef struct {
    int port;
    int index;
} work_item_t;

enum ports {
    PORT_CLOSED = 0,
    PORT_OPEN = 1,
};

int scan_port(char *host, int port, int seconds);
int* parse_single_port(char* str, int* count);
int* parse_port_range(char* str, int* count);
int* parse_port_list(char* str, int* count);
int resolve_hostname(const char* hostname, char* ip_buffer);

int threaded_scan_ports(scan_config_t *config, scan_result_t **results);

void* worker_thread(void* work_queue);
int get_next_port(work_queue_t *work_queue, work_item_t *item);
void save_result(work_queue_t *work_queue, work_item_t *item , int status);

void update_progress(int completed, int total);
void mark_port_completed(work_queue_t *work_queue);


#endif