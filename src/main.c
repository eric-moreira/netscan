#define _GNU_SOURCE
#include <stddef.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/select.h>
#include <netdb.h>
#include <stdlib.h>
#include "../include/scanner.h"


static void usage(char const *prog_name)
{
	printf("Usage: %s -h <host> -p <port> \n\t-t <timeout(sec)> -j <threads> -x (exclude closed ports)\n", prog_name);
}


int main(int argc, char *argv[])
{

	char *HOST = NULL;
	int *PORTS = NULL;
	int TIMEOUT = -1;
	int THREADS = 1;
	int count = 0;
	int exclude = 0;
	int opt;
	while ((opt = getopt(argc, argv, "h:p:t:j:xH")) != -1) {
		switch (opt) {
		case 'h':
			HOST = optarg;
			break;
		case 'p':
			PORTS = parse_port_list(optarg, &count);
			break;
		case 't':
			TIMEOUT = atoi(optarg);
			break;
		case 'j':
			THREADS = atoi(optarg);
			break;
		case 'x':
			exclude = 1;
			break;
		case 'H':
			usage(argv[0]);
			return 0;
		case '?':
			usage(argv[0]);
			return 1;
		}

	}

	if (HOST == NULL || PORTS == NULL) {
		usage(argv[0]);
		return 1;
	}

	char IP[INET_ADDRSTRLEN];
	if(resolve_hostname(HOST, IP) != 0){
		return -1;
	}
	
	printf("HOST: %s (%s)\n", HOST, IP);
	scan_config_t config = {
        .host = HOST,
        .ports = PORTS,
        .port_count = count,
        .thread_count = THREADS,  // You can adjust number of threads
        .timeout = TIMEOUT > 0 ? TIMEOUT : 2  // Default 2 seconds if not specified
    };

	scan_result_t *results = NULL;
	if(threaded_scan_ports(&config, &results) != 0){
		fprintf(stderr, "Scan failed \n");
		free(PORTS);
		return 1;
	}

	if(exclude){
		for(int i = 0; i < config.port_count; i++) {
			if(results[i].status){
				printf("Port %d: %s\n", 
					results[i].port,
					results[i].status == PORT_OPEN ? "open" : "closed");
			}
    	}
	} else {
		for(int i = 0; i < config.port_count; i++) {
        	printf("Port %d: %s\n", 
               results[i].port,
               results[i].status == PORT_OPEN ? "open" : "closed");
    	}
	}
	

	free(PORTS);
	free(results);
	

	return 0;
}
