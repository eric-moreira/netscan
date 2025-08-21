#include <stdio.h>
#include <assert.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../include/scanner.h"

// Simple test framework
#define TEST(name) void test_##name()
#define RUN_TEST(name) do { \
    printf("Running %s... \n", #name); \
    test_##name(); \
    printf("PASSED\n"); \
} while(0)

// Test helper: create a local TCP server for testing
int create_test_server(int port) {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) return -1;
    
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    
    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(server_fd);
        return -1;
    }
    
    if (listen(server_fd, 1) < 0) {
        close(server_fd);
        return -1;
    }
    
    return server_fd;
}

TEST(scan_open_port) {
    // Create test server on port 12345
    int server_fd = create_test_server(12345);
    assert(server_fd > 0);
    
    printf("target: 127.0.0.1\n");
    int result = scan_port("127.0.0.1", 12345, 2);
    assert(result == PORT_OPEN); // Should be open
    
    close(server_fd);
}

TEST(scan_closed_port) {
    printf("target: 127.0.0.1\n");
    int result = scan_port("127.0.0.1", 12346, 1);
    assert(result == PORT_CLOSED); // Should be closed
}

TEST(scan_with_hostname) {
    printf("target: localhost\n");
    int result = scan_port("localhost", 22, 2);
    assert(result == PORT_OPEN || result == PORT_CLOSED); // Could be either
}

TEST(scan_invalid_hostname) {
    printf("target: invalid.hostname.that.does.not.exist\n");
    int result = scan_port("invalid.hostname.that.does.not.exist", 80, 1);
    assert(result == -1); // Should fail with getaddrinfo error
}

TEST(scan_invalid_port_range) {
    // Test invalid ports
    printf("target: 127.0.0.1 port: -1\n");
    int result = scan_port("127.0.0.1", -1, 1);
    assert(result == -1); // Invalid port
    
    printf("target: 127.0.0.1 port: 0\n");
    result = scan_port("127.0.0.1", 0, 1);
    assert(result == -1); // Invalid port
    
    printf("target: 127.0.0.1 port: 65536\n");
    result = scan_port("127.0.0.1", 65536, 1);
    assert(result == -1); // Invalid port
    
    // Test valid port range boundaries
    printf("target: 127.0.0.1 port: 1\n");
    result = scan_port("127.0.0.1", 1, 1);
    assert(result >= PORT_CLOSED); // Valid port
    
    printf("target: 127.0.0.1 port: 65535\n");
    result = scan_port("127.0.0.1", 65535, 1);
    assert(result >= PORT_CLOSED); // Valid port
}

TEST(scan_timeout_functionality) {
    printf("target: 127.0.0.1\n");
    // Test with very short timeout
    int result = scan_port("127.0.0.1", 12347, 1);
    assert(result >= PORT_CLOSED);
    
    // Test with longer timeout
    printf("target: 127.0.0.1\n");
    result = scan_port("127.0.0.1", 12348, 5);
    assert(result >= PORT_CLOSED);
    
    // Test with zero timeout (should use default)
    printf("target: 127.0.0.1\n");
    result = scan_port("127.0.0.1", 12349, 0);
    assert(result >= PORT_CLOSED);
}

TEST(scan_well_known_services) {
    // Test some well-known ports
    printf("target: 8.8.8.8\n");
    int result = scan_port("8.8.8.8", 53, 3); // DNS
    assert(result >= PORT_CLOSED);
    
    printf("target: google.com\n");
    result = scan_port("google.com", 80, 3); // HTTP
    assert(result >= PORT_CLOSED);
    
    printf("target: localhost\n");
    result = scan_port("localhost", 22, 2); // SSH
    assert(result >= PORT_CLOSED);
}

TEST(scan_null_parameters) {
    // Test null hostname
    int result = scan_port(NULL, 80, 1);
    assert(result == -1);
    
    // Test invalid timeout
    printf("target: localhost\n");
    result = scan_port("localhost", 80, -1);
    assert(result >= PORT_CLOSED); // Should use default timeout
}

int main() {
    printf("=== Running Scanner Unit Tests ===\n\n");
    
    RUN_TEST(scan_open_port);
    printf("\n");
    RUN_TEST(scan_closed_port);
    printf("\n");
    RUN_TEST(scan_with_hostname);
    printf("\n");
    RUN_TEST(scan_invalid_hostname);
    printf("\n");
    RUN_TEST(scan_invalid_port_range);
    printf("\n");
    RUN_TEST(scan_timeout_functionality);
    printf("\n");
    RUN_TEST(scan_well_known_services);
    printf("\n");
    RUN_TEST(scan_null_parameters);
    printf("\n");
    
    printf("=== All tests passed! ===\n");
    return 0;
}