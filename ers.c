#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>

#define BUFFER_SIZE 1024

#define PAYLOAD_SIZE 64

typedef struct {
    uint32_t id;
    char payload[64];
} Entry;

typedef struct {
    int len;
    int capacity;
    Entry *items;
} EntryArray;

void entry_add(EntryArray *arr, Entry e) {
    if (arr->capacity == 0) {
        arr->capacity = 1;
        arr->items = malloc(sizeof(Entry) * arr->capacity);
    }

    if (arr->len >= arr->capacity) {
        assert(arr->len == arr->capacity);
        arr->capacity *= 2;
        arr->items = realloc(arr->items, sizeof(Entry) * arr->capacity);
    }

    arr->items[arr->len++] = e;
}

void entry_remove_unordered(EntryArray *arr, int i) {
    assert(i < arr->len);
    if (arr->len == 0) return;

    arr->items[i] = arr->items[arr->len-1];
    arr->len--;
};

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    int port = 54321;
    char *env_port_str = getenv("ERS_PORT");
    if (env_port_str != NULL) {
      int env_port = atoi(env_port_str);
      if (env_port > 0) port = env_port;
    }

    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;  // all local interfaces
    server_addr.sin_port = htons(port);

    int ret = bind(sock, (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (ret < 0) {
        printf("Could not bind port");
        exit(1);
    }

    printf("Server started on port %d\n", port);


    EntryArray entries = {0};

    bool exit = false;
    while (!exit) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        char buffer[BUFFER_SIZE];
        ssize_t len = recvfrom(
            sock,
            buffer,
            BUFFER_SIZE - 1,
            0,
            (struct sockaddr *)&client_addr,
            &client_len
        );

        if (len == (ssize_t) -1) continue;

        buffer[len] = 0;

        char *buf_ptr = buffer;
        char *cmd = strsep(&buf_ptr, " ");
        char *id_str = strsep(&buf_ptr, "\n");

        if (id_str == NULL) {
            char *reply = "ERROR\nNO ID ARGUMENT AFTER COMMAND\n";
            sendto(
                sock,
                reply,
                strlen(reply),
                0,
                (struct sockaddr *)&client_addr,
                client_len
            );
            continue;
        }
        uint32_t id = atoi(id_str);

        if (strcmp(cmd, "REGISTER") == 0) {
            while (buf_ptr != NULL) {
                char *line = strsep(&buf_ptr, "\n");
                int len = strlen(line);
                if (len == 0) continue;
                if (len > PAYLOAD_SIZE - 1) {
                    char reply[64];
                    int reply_len = snprintf(reply, sizeof(reply), "ERROR\nMAX PAYLOAD IS %d\n", PAYLOAD_SIZE - 1);
                    sendto(
                        sock,
                        reply,
                        reply_len,
                        0,
                        (struct sockaddr *)&client_addr,
                        client_len
                    );
                    continue;
                }

                Entry e = {
                    .id = id,
                };

                strncpy(e.payload, line, sizeof(e.payload));

                entry_add(&entries, e);
                
            }
            char reply[64];
            int reply_len = snprintf(reply, sizeof(reply), "REGISTERED %d\n", id);
            sendto(
                sock,
                reply,
                reply_len,
                0,
                (struct sockaddr *)&client_addr,
                client_len
            );
        } else if (strcmp(cmd, "QUERY") == 0) {
            char reply[BUFFER_SIZE];
            int offset = 0;
            offset += snprintf(reply + offset, sizeof(reply) - offset, "ENTRIES %d\n", id);
            for (int i = 0; i < entries.len; i++) {
                Entry e = entries.items[i];
                if (e.id != id) continue;

                offset += snprintf(reply + offset, sizeof(reply) - offset, "%s\n", e.payload);
                if (offset > (int)sizeof(reply) - 1) break;
            }

            sendto(
                sock,
                reply,
                offset,
                0,
                (struct sockaddr *)&client_addr,
                client_len
            );
        } else {
            char *reply = "ERROR\nCOMMAND DOES NOT EXISTIS\n";
            sendto(
                sock,
                reply,
                strlen(reply),
                0,
                (struct sockaddr *)&client_addr,
                client_len
            );
        }
    }
}
