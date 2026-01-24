#include <asm-generic/errno-base.h>
#include <asm-generic/errno.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/sendfile.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <assert.h>
#include <signal.h>
#include "art.h"
#define PORT 6379
#define IP_ADDR INADDR_LOOPBACK
#define BACKLOG 511
#define MAX_EVENTS 128
#define REQUEST_BUFF_LEN 4096
#define RESPONSE_BUFF_LEN 4096
#define MAX_ARGS 16
#define CRLF_LEN 2

typedef enum {
    STATE_READ,
    STATE_SEND,
    STATE_DONE,
} state_t;

typedef enum {
    IO_OK,
    IO_AGAIN,
    IO_ERR
} io_status_t;

typedef enum {
    PARSE_OK,
    PARSE_INCOMPLETE,
    PARSE_ERR
} parse_status_t;

typedef enum {
    TYPE_NULL,
    TYPE_STRING,
    TYPE_ERROR,
    TYPE_INT,
} type_t;

typedef struct {

    int client_fd;
    state_t state;
    type_t type;

    char request[REQUEST_BUFF_LEN];
    ssize_t request_len;
    ssize_t req_offset;
    ssize_t total_element;
    ssize_t read_element;
    ssize_t parse_index;

    char *argv[MAX_ARGS];

    char response[RESPONSE_BUFF_LEN];
    ssize_t response_len;
    ssize_t res_offset;

} client_t;

// Helper
int set_nonblocking(int fd);
int setup_server_socket();
int init_epoll(int server_fd);
void get_client_ip(int client_fd, char *buffer, size_t buff_len);

// Core networking 
void handle_new_connection(int epoll_fd, int server_fd);
void handle_client_event(int epoll_fd, client_t *client);
void free_client(client_t *client);
void cleanup_connection(client_t *client);

// State handler 
void handle_state_read(int epoll_fd, client_t *client);
void handle_state_send(int epoll_fd, client_t *client);

// IO & Parsing
io_status_t io_reader(client_t *client);
parse_status_t parse_request(client_t *client);
void process_command(client_t *client);

int main() {
    signal(SIGPIPE, SIG_IGN);
    int server_fd = setup_server_socket();
    int epoll_fd = init_epoll(server_fd);
    printf("minikart is listening on port %d...\n", PORT);

    // Event loop
    struct epoll_event events[MAX_EVENTS] = {0};
    for (;;) {
        int ready_events = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        if (ready_events < 0 && errno != EINTR) {
            perror("Epoll wait failed");
            close(server_fd);
            close(epoll_fd);
            exit(EXIT_FAILURE);
        }

        for (int i = 0; i < ready_events; i++) {
            if(events[i].data.ptr == NULL) {
                handle_new_connection(epoll_fd, server_fd);
            } else {
                client_t *client = (client_t *)events[i].data.ptr;
                handle_client_event(epoll_fd, client);
            }
        }
    }

    return 0;
}

int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

// Returns server_fd if sucess, crash if failed
int setup_server_socket() {
    // Create server socket
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("Socket creation failed");
		exit(EXIT_FAILURE);
    }

    // Configure socket for reusable address/port
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
		perror("Setsockopt failed");
        close(server_fd);
		exit(EXIT_FAILURE);
	}

    // Bind
    struct sockaddr_in addr = {0};
	addr.sin_family = AF_INET;
	addr.sin_port = htons(PORT); 
	addr.sin_addr.s_addr = htonl(IP_ADDR);

	if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("Bind failed");
        close(server_fd);
		exit(EXIT_FAILURE);
	}

    // Listen
	if (listen(server_fd, BACKLOG) < 0) {
		perror("Listen failed");
        close(server_fd);
		exit(EXIT_FAILURE);
	}

    // Non-blocking for epoll
    if (set_nonblocking(server_fd) < 0) {
        perror("Set nonblocking failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    return server_fd;
}

int init_epoll(int server_fd) {
    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        perror("Epoll create failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // Create an epoll event triggers
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.ptr = NULL;

    // Hand it to the kernel
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &ev) < 0) {
        perror("Epoll ctl failed");
        close(server_fd);
        close(epoll_fd);
        exit(EXIT_FAILURE);
    }
    return epoll_fd;
}

void handle_new_connection(int epoll_fd, int server_fd) {
    printf("You got a new connection!\n");
    struct sockaddr_in client_addr;
    socklen_t socklen = sizeof(client_addr);

    int client_fd = accept(
        server_fd,
        (struct sockaddr *)&client_addr,
        &socklen
    );

    if (client_fd < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return;
        perror("Accept failed");
        return;
    }

    if (set_nonblocking(client_fd) < 0) {
        perror("Set nonblocking failed");
        close(client_fd);
        return;
    }

    client_t *client = calloc(1, sizeof(client_t));
    if (!client) {
        perror("Memory allocation failed");
        close(client_fd);
        return;
    }

    client->client_fd = client_fd;
    client->state = STATE_READ;

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.ptr = client;

    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &ev) < 0) {
        perror("Epoll ctl failed");
        close(client_fd);
        free(client);
        return;
    }
}

void free_client(client_t *client) {
    if (!client) return;

    if (client->client_fd > 0)
        close(client->client_fd);
    free(client);
}

void process_command(client_t *client) {
    if (!client || client->total_element == 0) return;

    if (strcasecmp(client->argv[0], "PING") == 0) {
        const char *reply = "+PONG\r\n";
        size_t len = strlen(reply);
        memcpy(client->response, reply, len);
        client->response_len = len; 
        return;
    }

    // Default: Unknown Command
    const char *err = "-ERR unknown command\r\n";
    memcpy(client->response, err, strlen(err));
    client->response_len = strlen(err);
}

void cleanup_connection(client_t *client) {
    // After sending the response, need to check 
    // if there is leftovers in the request buffer
    ssize_t leftovers = client->request_len - client->parse_index;
    if (leftovers > 0) {
        // Shift and zero out the memory
        memmove(client->request, client->request + client->parse_index, leftovers);
        memset(client->request + leftovers, 0, client->request_len - leftovers);
        client->req_offset = leftovers;
    }
    else {
        memset(client->request, 0, client->request_len);
        client->req_offset = 0;
    }
    client->response_len = 0;
    client->request_len = 0;
    client->total_element = 0;
    client->res_offset = 0;
    client->parse_index = 0;
    client->read_element = 0;
}

void get_client_ip(int client_fd, char *buffer, size_t buff_len) {
    struct sockaddr_in addr;
    socklen_t socklen = sizeof(addr);
    if (getpeername(client_fd, (struct sockaddr*)&addr, &socklen) == -1) {
        perror("Failed to get client address");
        strncpy(buffer, "Unknown", buff_len);
        return;
    }
    if (inet_ntop(AF_INET, &addr.sin_addr, buffer, buff_len) == NULL) {
        perror("inet_top failed");
        strncpy(buffer, "Unknown", buff_len);
    }
}

void handle_state_send(int epoll_fd, client_t *client) {
    ssize_t bytes_sent = write(
        client->client_fd,
        client->response + client->res_offset,
        client->response_len - client->res_offset
    );

    if (bytes_sent < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return;
        perror("Write response failed");
        free_client(client);
        return;
    }

    client->res_offset += bytes_sent;
    
    if (client->res_offset == client->response_len) {
        cleanup_connection(client);
        client->state = STATE_READ;
        struct epoll_event ev;
        ev.events = EPOLLIN;
        ev.data.ptr = client;

        if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, client->client_fd, &ev) < 0) {
            perror("Epoll add back connection failed");
            free_client(client);
        }
        
        // If there is leftovers, proceed to trigger read
        if (client->req_offset > 0) {
            handle_state_read(epoll_fd, client);
        }
    }
}

io_status_t io_reader(client_t *client) {
    if (REQUEST_BUFF_LEN - client->req_offset < 2) {
        printf("Buffer full!\n");
        return IO_ERR;
    }

    ssize_t bytes_read = read(
        client->client_fd,
        client->request + client->req_offset,
        REQUEST_BUFF_LEN - client->req_offset - 1
    );

    if (bytes_read < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // Try again
            return IO_AGAIN;
        }
        perror("Read request failed");
        return IO_ERR;
    }

    if (bytes_read == 0) {
        // The client want to close connection
        char client_ipv4[32];
        socklen_t ipv4_len = 32;
        get_client_ip(client->client_fd, client_ipv4, ipv4_len);
        
        printf("Client %s has closed connection.\n", client_ipv4);
        return IO_ERR;
    }
    assert(bytes_read > 0);
    client->req_offset += bytes_read;
    client->request[client->req_offset] = '\0';

    return IO_OK;
}


parse_status_t parse_request(client_t *client) {
    // I need to parse how many element
    // (will) be in the request
    if (client->request[0] != '*') {
        printf("Strange prefix '%c', ignore...\n", client->request[0]);
        return PARSE_ERR;
    }

    // If total element is not known yet
    if (client->total_element == 0) {
        char *location = strstr(client->request, "\r\n");
        if (location) {
            // We got at least the number of elements
            // Parse it
            if (sscanf(client->request, "*%ld\r\n", &(client->total_element)) != 1) return PARSE_ERR;
            if (client->total_element > MAX_ARGS || client->total_element <= 0) return PARSE_ERR;
            client->parse_index = (location - client->request) + CRLF_LEN;
        } else {
            // Can't parse the total element now, wait more
            return PARSE_INCOMPLETE;
        }
    }

    // Okay we have num element at this point
    // Lets try to read it to see if we got a new element in this package
    while (client->read_element < client->total_element) {
        // Out of bound error
        if (client->parse_index >= client->req_offset) return PARSE_INCOMPLETE;

        if (client->request[client->parse_index] != '$') {
            printf("Trying to parse a string with $ but found %c\n", client->request[client->parse_index]);
            return PARSE_ERR;
        }

        char *location = strstr(client->request + client->parse_index, "\r\n");
        if (!location) {
            // There is no \r\n, stop and wait. 
            return PARSE_INCOMPLETE;
        }

        // Parse the length of the element
        int len_next_elem;
        if (sscanf(client->request + client->parse_index, "$%d\r\n", &len_next_elem) != 1) return PARSE_ERR;
        if (len_next_elem < 0) return PARSE_ERR;
        ssize_t skip = (location - (client->request + client->parse_index)) + CRLF_LEN + len_next_elem + CRLF_LEN;

        // And then jump
        if (client->parse_index + skip > client->req_offset) {
            // Out of bound
            return PARSE_INCOMPLETE;
        }
        else {
            client->argv[client->read_element] = location + CRLF_LEN;
            *(location + CRLF_LEN + len_next_elem) = '\0';
            printf("argv[%ld]: %s\n", client->read_element, client->argv[client->read_element]);
            client->parse_index += skip;
            client->read_element++;
        }

    }
    return PARSE_OK;
}

void handle_state_read(int epoll_fd, client_t *client) {
    io_status_t read_status = io_reader(client);
    if (read_status == IO_ERR) {
        free_client(client);
        return;
    }
    else if (read_status == IO_AGAIN && client->req_offset == 0) return;

    parse_status_t parse_status = parse_request(client);
    if (parse_status == PARSE_ERR) {
        free_client(client);
        return;
    }
    else if (parse_status == PARSE_INCOMPLETE) return;

    // If done reading, modify the epoll to be write-ready
    assert(client->read_element == client->total_element);
    // This will modify the response buffer
    process_command(client);

    client->state = STATE_SEND;
    client->request_len = client->req_offset;

    // Change to write mode
    struct epoll_event ev;
    ev.events = EPOLLOUT;
    ev.data.ptr = client;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, client->client_fd, &ev) < 0) {
        perror("Epoll_ctl failed");
        free_client(client);
        return;
    }
}


void handle_client_event(int epoll_fd, client_t *client) {
    if (!client) return;
    (void)epoll_fd;

    switch (client->state) {

        case STATE_READ:
            handle_state_read(epoll_fd, client);
            break;
        case STATE_SEND:
            handle_state_send(epoll_fd, client);
            break;
        case STATE_DONE:
            break;

    }
}