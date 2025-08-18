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
	int PORT = -1;
        int TIMEOUT = -1;
	int opt;
	
	while ((opt = getopt(argc, argv, "h:p:t:")) != -1) {
		switch (opt) {
		case 'h':
			HOST = optarg;
			break;
		case 'p':
			PORT = atoi(optarg);
			break;
                case 't':
                        TIMEOUT = atoi(optarg);
                        break;
		case '?':
			usage(argv[0]);
			return 1;
		}

	}

	if (HOST == NULL || PORT == -1) {
		usage(argv[0]);
		return 1;
	}

	if (PORT <= 0 || PORT > 65535) {
		printf("Invalid port: %d\n", PORT);
		return 1;
	}

        scan_port(HOST, PORT, TIMEOUT);
	
	return 0;
}
