#include <stdint.h>
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
#define REQUEST_BUFF_LEN 4000
#define RESPONSE_BUFF_LEN 4000
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
    size_t len;
    char data[];
} blob_t;

typedef struct {
    int fd;
    uint32_t state;

    struct {
        char buf[REQUEST_BUFF_LEN];
        uint32_t len;
        uint32_t scan_pos;
    } input;

    struct {
        blob_t *args[MAX_ARGS];
        uint32_t count;
        uint32_t parsed;
    } cmd;

    struct {
        char buf[RESPONSE_BUFF_LEN];
        uint32_t len;
        uint32_t sent_pos;
    } output;

} client_t;

// Helper
int set_nonblocking(int fd);
int server_init();
int epoll_init(int server_fd);
void get_client_ip(int client_fd, char *buffer, size_t buff_len);
blob_t *blob_create(const char *src, size_t len);

// Core networking 
void accept_connection(int epoll_fd, int server_fd);
void free_client(client_t *client);
void conn_reset(client_t *client);
void on_event(int epoll_fd, client_t *client);

// State handler 
void on_read(int epoll_fd, client_t *client);
void on_write(int epoll_fd, client_t *client);

// Command handler
void do_set(client_t *client);
void do_get(client_t *client);
void do_del(client_t *client);

// IO & Parsing
io_status_t sys_read(client_t *client);
parse_status_t parse_request(client_t *client);
void exec_cmd(client_t *client);

static art_tree g_keyspace;

int main() {
    signal(SIGPIPE, SIG_IGN);

    if (art_tree_init(&g_keyspace) != 0) {
        perror("Failed to init ART keyspace");
        exit(EXIT_FAILURE);
    }

    int server_fd = server_init();
    int epoll_fd = epoll_init(server_fd);
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
                accept_connection(epoll_fd, server_fd);
            } else {
                client_t *client = (client_t *)events[i].data.ptr;
                on_event(epoll_fd, client);
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
int server_init() {
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

int epoll_init(int server_fd) {
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

void accept_connection(int epoll_fd, int server_fd) {
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

    client->fd = client_fd;
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

    if (client->fd > 0)
        close(client->fd);
    free(client);
}

void exec_cmd(client_t *client) {
    if (!client || client->cmd.count == 0) return;

    blob_t *cmd = client->cmd.args[0];

    if (cmd->len == 4 && strncasecmp(client->cmd.args[0]->data, "PING", 4) == 0) {
        const char *reply = "+PONG\r\n";
        size_t len = strlen(reply);
        memcpy(client->output.buf, reply, len);
        client->output.len = len; 
        return;
    }

    else if (cmd->len == 3 && strncasecmp(cmd->data, "SET", 3) == 0) {
        do_set(client);
        return;
    }

    else if (cmd->len == 3 && strncasecmp(cmd->data, "GET", 3) == 0) {
        do_get(client);
        return;
    }

    else if (cmd->len == 3 && strncasecmp(cmd->data, "DEL", 3) == 0) {
        do_del(client);
        return;
    }

    // Default: Unknown Command
    const char *err = "-ERR unknown command\r\n";
    memcpy(client->output.buf, err, strlen(err));
    client->output.len = strlen(err);
}

void conn_reset(client_t *client) {
    // After sending the response, need to check 
    // if there is leftovers in the request buffer
    ssize_t leftovers = client->input.len - client->input.scan_pos;
    // Free the current args blob first.
    size_t cmd_count = client->cmd.count;
    for (size_t i = 0; i < cmd_count; i++) {
        free(client->cmd.args[i]);
        client->cmd.args[i] = NULL;
    }

    // Buffer management logic (shifting)
    if (leftovers > 0) {
        // Shift and zero out the memory
        memmove(client->input.buf, client->input.buf + client->input.scan_pos, leftovers);
        memset(client->input.buf + leftovers, 0, client->input.len - leftovers);
        client->input.len = leftovers;
    }
    else {
        memset(client->input.buf, 0, client->input.len);
        client->input.len = 0;
    }
    client->output.len = 0;
    // Note: client->input.len was previously used as request_len 
    // It is updated above in the shift logic.
    client->cmd.count = 0;
    client->output.sent_pos = 0;
    client->input.scan_pos = 0;
    client->cmd.parsed = 0;
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

void on_write(int epoll_fd, client_t *client) {
    ssize_t bytes_sent = write(
        client->fd,
        client->output.buf + client->output.sent_pos,
        client->output.len - client->output.sent_pos
    );

    if (bytes_sent < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return;
        perror("Write response failed");
        free_client(client);
        return;
    }

    client->output.sent_pos += bytes_sent;
    
    // Check if we have sent the full response
    if (client->output.sent_pos == client->output.len) {
        conn_reset(client);
        client->state = STATE_READ;
        
        struct epoll_event ev;
        ev.events = EPOLLIN;
        ev.data.ptr = client;

        if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, client->fd, &ev) < 0) {
            perror("Epoll add back connection failed");
            free_client(client);
            return;
        }
        
        // Pipeline Optimization:
        // If conn_reset() found leftovers (input.len > 0),
        // we immediately process them as the next request.
        if (client->input.len > 0) {
            on_read(epoll_fd, client);
        }
    }
}

io_status_t sys_read(client_t *client) {
    // Check if buffer is full (need at least 1 byte + 1 null terminator)
    if (REQUEST_BUFF_LEN - client->input.len < 2) {
        printf("Buffer full!\n");
        return IO_ERR;
    }

    ssize_t bytes_read = read(
        client->fd,
        client->input.buf + client->input.len,
        REQUEST_BUFF_LEN - client->input.len - 1
    );

    if (bytes_read < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // Socket is not ready yet, try again later
            return IO_AGAIN;
        }
        perror("Read request failed");
        return IO_ERR;
    }

    if (bytes_read == 0) {
        // The client want to close connection
        char client_ipv4[32];
        get_client_ip(client->fd, client_ipv4, sizeof(client_ipv4));
        
        printf("Client %s has closed connection.\n", client_ipv4);
        return IO_ERR;
    }
    
    assert(bytes_read > 0);
    client->input.len += bytes_read;
    if (client->input.len < REQUEST_BUFF_LEN) {
        client->input.buf[client->input.len] = '\0'; // Safety null-termination
    }

    return IO_OK;
}


parse_status_t parse_req(client_t *client) {
    // Alias for cleaner code, compiler will optimize it away
    char *buf = client->input.buf; 

    // 1. Basic Validation
    if (buf[0] != '*') {
        printf("Strange prefix '%c', ignore...\n", buf[0]);
        return PARSE_ERR;
    }

    // 2. Parse Command Count (*3\r\n)
    // If we haven't determined the total arguments yet:
    if (client->cmd.count == 0) {
        char *line_end = strstr(buf, "\r\n");
        if (!line_end) {
            return PARSE_INCOMPLETE;
        }

        // We found the first line, parse the count
        uint32_t count = 0;
        for (char *p = buf + 1; p < line_end; p++) {
            char c = *p;
            if (c < '0' || c > '9') return PARSE_ERR;
            count = (count * 10) + (c - '0');
        }
        
        if (count > MAX_ARGS || count <= 0) return PARSE_ERR;
        
        client->cmd.count = count;
        client->input.scan_pos = (line_end - buf) + CRLF_LEN;
    }

    // 3. Parse Arguments ($3\r\nSET\r\n)
    while (client->cmd.parsed < client->cmd.count) {
        
        // Ensure we don't read past what we have received
        if (client->input.scan_pos >= client->input.len) return PARSE_INCOMPLETE;

        // Verify prefix '$' for Bulk Strings
        if (buf[client->input.scan_pos] != '$') {
            printf("Expected '$', found '%c'\n", buf[client->input.scan_pos]);
            return PARSE_ERR;
        }

        // Skip '$'
        client->input.scan_pos++;
        int len_next_cmd = 0;

        // Parse the length integer manually
        while (1) {
            if (client->input.scan_pos >= client->input.len) {
                return PARSE_INCOMPLETE;
            }

            char c = buf[client->input.scan_pos];

            if (c == '\r') {
                if (client->input.scan_pos + 1 >= client->input.len) {
                    return PARSE_INCOMPLETE;
                }
                if (buf[client->input.scan_pos + 1] != '\n') {
                    return PARSE_ERR;
                }
                client->input.scan_pos += 2; // Skip \r\n
                break;
            }
            
            if (c < '0' || c > '9') {
                printf("Protocol Error: Expected digit, got '%c'", c);
                return PARSE_ERR;
            }

            len_next_cmd = (len_next_cmd * 10) + (c - '0');
            client->input.scan_pos++;
        }

        if (len_next_cmd < 0) return PARSE_ERR;

        // Check if we have the FULL argument in the buffer
        if (client->input.scan_pos + len_next_cmd + CRLF_LEN > client->input.len) {
            return PARSE_INCOMPLETE;
        }

        // We have the full string! Set the pointer.
        
        blob_t *new_blob = blob_create(buf + client->input.scan_pos, len_next_cmd);
        if (!new_blob) return PARSE_ERR;

        client->cmd.args[client->cmd.parsed] = new_blob;

        // Advance cursor and counter
        client->input.scan_pos += len_next_cmd + CRLF_LEN;
        client->cmd.parsed++;
    }

    return PARSE_OK;
}

void on_read(int epoll_fd, client_t *client) {
    io_status_t read_status = sys_read(client);
    
    if (read_status == IO_ERR) {
        free_client(client);
        return;
    }
    // If no data is available (EAGAIN) and we have an empty buffer, stop and wait.
    // If buffer is NOT empty, we might have enough data from a previous read to parse.
    else if (read_status == IO_AGAIN && client->input.len == 0) return;

    parse_status_t parse_status = parse_req(client);
    
    if (parse_status == PARSE_ERR) {
        free_client(client);
        return;
    }
    else if (parse_status == PARSE_INCOMPLETE) {
        // Not enough data for a full command yet, wait for next EPOLLIN
        return;
    }

    // Sanity check: Parser claims success, so we must have all arguments
    assert(client->cmd.parsed == client->cmd.count);
    
    // Execute command (fills client->output.buf)
    exec_cmd(client);

    client->state = STATE_SEND;
    
    // Note: Old code assigned request_len = req_offset here.
    // In new struct, client->input.len is already the correct length, so we skip it.

    // Change Epoll state to WRITE (EPOLLOUT)
    struct epoll_event ev;
    ev.events = EPOLLOUT;
    ev.data.ptr = client;
    
    if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, client->fd, &ev) < 0) {
        perror("Epoll_ctl failed");
        free_client(client);
        return;
    }
}


void on_event(int epoll_fd, client_t *client) {
    if (!client) return;
    (void)epoll_fd;

    switch (client->state) {

        case STATE_READ:
            on_read(epoll_fd, client);
            break;
        case STATE_SEND:
            on_write(epoll_fd, client);
            break;
        case STATE_DONE:
            break;

    }
}

blob_t *blob_create(const char *src, size_t len) {
    blob_t *b = malloc(sizeof *b + len + 1);
    if (!b) return NULL;
    b->len = len;
    memcpy(b->data, src, len);
    b->data[len] = '\0';
    return b;
}

void do_set(client_t *client) {
    if (client->cmd.count != 3) {
        const char *err = "-ERR wrong number of arguments for 'SET'\r\n";
        memcpy(client->output.buf, err, strlen(err));
        client->output.len = strlen(err);
        return;
    }

    blob_t *data_blob = blob_create(client->cmd.args[2]->data, client->cmd.args[2]->len);
    
    blob_t *old_blob = art_insert(
        &g_keyspace, 
        (const unsigned char *)client->cmd.args[1]->data, 
        client->cmd.args[1]->len, 
        data_blob
    );

    if (old_blob != NULL) {
        free(old_blob);
    }

    const char *ok = "+OK\r\n";
    memcpy(client->output.buf, ok, strlen(ok));
    client->output.len = strlen(ok);
}

void do_get(client_t *client) {
    if (client->cmd.count != 2) {
        const char *err = "-ERR wrong number of arguments for 'GET'\r\n";
        memcpy(client->output.buf, err, strlen(err));
        client->output.len = strlen(err);
        return;
    }

    blob_t *result = art_search(
        &g_keyspace,
        (const unsigned char *)client->cmd.args[1]->data,
        client->cmd.args[1]->len
    );

    // Key not found
    if (result == NULL) {
        const char *err = "$-1\r\n";
        memcpy(client->output.buf, err, strlen(err));
        client->output.len = strlen(err);
        return;
    }

    int header_len = snprintf(client->output.buf, RESPONSE_BUFF_LEN, "$%zu\r\n", result->len);
    memcpy(client->output.buf + header_len, result->data, result->len);
    memcpy(client->output.buf + header_len + result->len, "\r\n", 2);
    client->output.len = header_len + result->len + 2;
}

void do_del(client_t *client) {
    size_t cmd_count = client->cmd.count;
    blob_t **args = client->cmd.args;
    if (cmd_count < 2) {
        const char *err = "-ERR wrong number of arguments for 'DEL'\r\n";
        memcpy(client->output.buf, err, strlen(err));
        client->output.len = strlen(err);
        return;
    }
    uint32_t delete_count = 0;
    for (size_t i = 1; i < cmd_count; i++) {
        blob_t *result = art_delete(&g_keyspace, (const unsigned char*)args[i]->data, args[i]->len);
        if (result != NULL) {
            free(result);
            delete_count++;
        }
    }

    client->output.len = snprintf(client->output.buf, RESPONSE_BUFF_LEN, ":%d\r\n", delete_count);
}