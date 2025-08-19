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
#include "../include/scanner.h"

int scan_port(char *host, int port, int seconds)
{	
	if(port < 0 || port > 65535){
		printf("Invalid port \n");
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
		printf("%d : closed  (error: timeout)\n", port);
		return 0;
	}
	int error = 0;
	socklen_t len = sizeof(error);

	if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &len) == 0) {
		if (error == 0) {
			printf("%d : open\n", port);
		} else {
			printf("%d : closed  (error: %s)\n", port,
				   strerror(error));
		}
	}

	freeaddrinfo(result);

	close(sock);
	return 0;

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