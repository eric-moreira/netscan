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
    
    // Test scanning the open port
    int result = scan_port("127.0.0.1", 12345, 2);
    assert(result == 0); // Should complete successfully
    
    close(server_fd);
}

TEST(scan_closed_port) {
    // Test scanning a port that should be closed
    // Using port 12346 which we don't bind to
    int result = scan_port("127.0.0.1", 12346, 1);
    assert(result == 0); // Should complete (but show closed)
}

TEST(scan_with_hostname) {
    // Test hostname resolution
    int result = scan_port("localhost", 22, 2);
    assert(result == 0); // Should resolve and complete
}

TEST(scan_invalid_hostname) {
    // Test with invalid hostname
    int result = scan_port("invalid.hostname.that.does.not.exist", 80, 1);
    assert(result == -1); // Should fail with getaddrinfo error
}

TEST(scan_invalid_port_range) {
    // Note: This tests the main() logic, but we'll test edge cases
    // For now, test valid port ranges that our function handles
    int result = scan_port("127.0.0.1", 1, 1);
    assert(result == 0); // Port 1 is valid
    
    result = scan_port("127.0.0.1", 65535, 1);
    assert(result == 0); // Port 65535 is valid
}

TEST(scan_timeout_functionality) {
    // Test that timeout parameter is respected
    // This is harder to test precisely, but we can verify it doesn't crash
    int result = scan_port("127.0.0.1", 12347, 1); // 1 second timeout
    assert(result == 0);
    
    result = scan_port("127.0.0.1", 12348, 5); // 5 second timeout
    assert(result == 0);
}

TEST(scan_well_known_services) {
    // Test scanning some well-known services that might be running
    // These are non-intrusive tests
    
    // Test Google DNS (should be reachable)
    int result = scan_port("8.8.8.8", 53, 3);
    assert(result == 0); // Should complete
    
    // Test Google web server
    result = scan_port("google.com", 80, 3);
    assert(result == 0); // Should complete
}

int main() {
    printf("=== Running Scanner Unit Tests ===\n");
    
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
    
    printf("\n=== All tests passed! ===\n");
    return 0;
}