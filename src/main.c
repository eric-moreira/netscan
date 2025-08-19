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
	printf("Usage: %s -h <host> -p <port>\n", prog_name);
}


int main(int argc, char *argv[])
{

	char *HOST = NULL;
	int *PORTS = NULL;
	int TIMEOUT = -1;
	int count = 0;
	int opt;
	while ((opt = getopt(argc, argv, "h:p:t:")) != -1) {
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
	
	if(TIMEOUT != 0)
		printf("HOST: %s (%s)\n", HOST, IP);

	return 0;
}
