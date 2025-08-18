#define _GNU_SOURCE
#include <stddef.h>
#include <string.h>
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

#define MAX_EVENTS 64

static void usage(char const *prog_name)
{
	printf("Usage: %s -h <host> -p <port>\n", prog_name);
}

static int scan_port(char *host, int port, int seconds){
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

	printf("IP: %s \n", inet_ntoa(addr_in->sin_addr));

	addr_in->sin_port = htons(port);	// LEndian 0x0050 p/ BEndian 0x5000

        int res = connect(sock, (struct sockaddr*)addr_in, sizeof(*addr_in));

        if (res == -1 && errno != EINPROGRESS){
                fprintf(stderr, "error in connect() %d\n", errno);
                return -1;
        }

        fd_set socket_fds;
        FD_ZERO(&socket_fds);
        FD_SET(sock, &socket_fds);

        struct timeval timeout;
        timeout.tv_sec = 3;
        timeout.tv_usec = 0;
        if(seconds > 0){
                timeout.tv_sec = seconds;
                timeout.tv_usec = 0;
        } 
        

        int num_ready_sockets = select(sock + 1, NULL, &socket_fds, NULL, &timeout);

        if(num_ready_sockets <= 0){
                        printf("%d : closed  (error: timeout)\n", port);
                        return 0;
        }
        int error = 0;
        socklen_t len = sizeof(error);

        if(getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &len) == 0){
                if(error == 0){
                        printf("%d : open\n", port);
                } else {
                        printf("%d : closed  (error: %s)\n", port, strerror(error));
                }
        }

	freeaddrinfo(result);

	close(sock);
        return 0;

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
