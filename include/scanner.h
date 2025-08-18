#ifndef SCANNER_H
#define SCANNER_H


int scan_port(char *host, int port, int seconds);
int* parse_single_port(char* str, int* count);
int* parse_port_range(char* str, int* count);
int* parse_port_list(char* str, int* count);
int* parse_ports(char* str, int* count);


#endif