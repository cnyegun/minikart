#include <asm-generic/errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
#define PORT 6379
#define IP_ADDR INADDR_LOOPBACK
#define BACKLOG 511
#define MAX_EVENTS 128
#define REQUEST_BUFF_LEN 4096
#define RESPONSE_BUFF_LEN 4096

typedef enum {
    STATE_READ,
    STATE_SEND,
    STATE_DONE,
} state_t;

typedef struct {
    int client_fd;
    state_t state;

    char request[REQUEST_BUFF_LEN];
    size_t request_len;

    char response[RESPONSE_BUFF_LEN];
    size_t response_len;
    size_t response_sent;
} client_t;

int setup_server_socket();
int init_epoll(int server_fd);
void handle_new_connection(int epoll_fd, int server_fd);
void handle_client_event(int epoll_fd, client_t *client);

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

void handle_client_event(int epoll_fd, client_t *client) {
    if (!client) return;
    (void)epoll_fd;

    switch (client->state) {

        case STATE_READ:
            break;
        case STATE_SEND:
            break;
        case STATE_DONE:
            break;

    }
}