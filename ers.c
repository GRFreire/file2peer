#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define BUFFER_SIZE 1024    /* tamanho máximo de um datagrama recebido/enviado */
#define PAYLOAD_SIZE 64     /* tamanho máximo (com '\0') de um texto registrado */
#define DEFAULT_PORT 54321  /* porta UDP usada quando ERS_PORT não está definida */

/** Um registro: um texto associado a um ID de sessão. */
typedef struct {
  uint32_t id;
  char payload[PAYLOAD_SIZE];
} Entry;

/** Vetor dinâmico de registros (cresce dobrando a capacidade). */
typedef struct {
  int len;
  int capacity;
  Entry *items;
} EntryArray;

/** Vira 0 quando chega SIGINT/SIGTERM, o que faz o laço principal terminar. */
static volatile sig_atomic_t running = 1;

/** Tratador de sinais: apenas pede para o laço principal parar. */
static void handle_signal(int sig) {
  (void)sig;
  running = 0;
}

/**
 * Adiciona um registro ao vetor.
 * @return 0 em sucesso, -1 se faltou memória (o vetor continua válido).
 */
int entry_add(EntryArray *arr, Entry e) {
  if (arr->len >= arr->capacity) {
    int new_capacity = (arr->capacity == 0) ? 1 : arr->capacity * 2;

    /* Usa um ponteiro temporário: se realloc falhar, o vetor antigo não se perde. */
    Entry *new_items = realloc(arr->items, sizeof(Entry) * (size_t)new_capacity);
    if (new_items == NULL) {
      return -1;
    }
    arr->items = new_items;
    arr->capacity = new_capacity;
  }

  arr->items[arr->len++] = e;
  return 0;
}

/**
 * Remove o registro i trocando-o pelo último (não preserva a ordem).
 * Ainda não é usada; fica reservada para expirar registros antigos.
 */
void entry_remove_unordered(EntryArray *arr, int i) {
  if (arr->len == 0) return;
  assert(i >= 0 && i < arr->len);

  arr->items[i] = arr->items[arr->len - 1];
  arr->len--;
}

/**
 * Envia uma resposta de volta ao cliente.
 * Falha de envio não derruba o servidor (o cliente pode ter sumido e, em UDP,
 * ele reenvia o pedido); apenas registra o problema em stderr.
 * @return 0 em sucesso, -1 em falha.
 */
int send_reply(int sock, const struct sockaddr_in *client_addr, socklen_t client_len, const char *msg,
               size_t msg_len) {
  ssize_t sent = sendto(sock, msg, msg_len, 0, (const struct sockaddr *)client_addr, client_len);
  if (sent == -1) {
    fprintf(stderr, "sendto failed: %s\n", strerror(errno));
    return -1;
  }
  return 0;
}

/** Envia uma resposta de erro no formato "ERROR\n<motivo>\n". */
void send_error(int sock, const struct sockaddr_in *client_addr, socklen_t client_len,
                const char *reason) {
  char reply[BUFFER_SIZE];
  int reply_len = snprintf(reply, sizeof(reply), "ERROR\n%s\n", reason);
  if (reply_len < 0 || (size_t)reply_len >= sizeof(reply)) return;

  send_reply(sock, client_addr, client_len, reply, (size_t)reply_len);
}

/**
 * Interpreta o ID recebido (inteiro decimal sem sinal de 32 bits).
 * @return 0 em sucesso, -1 se o texto não for um ID válido.
 */
int parse_id(const char *str, uint32_t *out_id) {
  char *end = NULL;
  errno = 0;
  unsigned long value = strtoul(str, &end, 10);

  if (end == str || *end != '\0' || errno == ERANGE || value > UINT32_MAX) {
    return -1;
  }

  *out_id = (uint32_t)value;
  return 0;
}

/**
 * Descobre a porta UDP em que o servidor deve escutar (ERS_PORT ou padrão).
 * @return 0 em sucesso, -1 se ERS_PORT estiver definida com valor inválido.
 */
int get_listen_port(int *out_port) {
  *out_port = DEFAULT_PORT;

  const char *env_port_str = getenv("ERS_PORT");
  if (env_port_str == NULL) return 0;

  char *end = NULL;
  errno = 0;
  long env_port = strtol(env_port_str, &end, 10);
  if (end == env_port_str || *end != '\0' || errno == ERANGE || env_port < 1 || env_port > 65535) {
    fprintf(stderr, "Invalid ERS_PORT '%s' (expected a number from 1 to 65535)\n", env_port_str);
    return -1;
  }

  *out_port = (int)env_port;
  return 0;
}

int main(void) {
  int exit_code = EXIT_FAILURE;
  EntryArray entries = {0};

  int port;
  if (get_listen_port(&port) != 0) {
    return EXIT_FAILURE;
  }

  /* Sem SA_RESTART: assim recvfrom() é interrompido pelo sinal e o laço vê `running == 0`. */
  struct sigaction sa = {0};
  sa.sa_handler = handle_signal;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  if (sigaction(SIGINT, &sa, NULL) == -1 || sigaction(SIGTERM, &sa, NULL) == -1) {
    fprintf(stderr, "Could not install signal handlers: %s\n", strerror(errno));
    return EXIT_FAILURE;
  }

  int sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock == -1) {
    fprintf(stderr, "Could not create UDP socket: %s\n", strerror(errno));
    return EXIT_FAILURE;
  }

  struct sockaddr_in server_addr = {0};
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = INADDR_ANY;  /* todas as interfaces locais */
  server_addr.sin_port = htons((uint16_t)port);

  if (bind(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
    fprintf(stderr, "Could not bind UDP port %d: %s\n", port, strerror(errno));
    close(sock);
    return EXIT_FAILURE;
  }

  printf("Server started on port %d\n", port);

  while (running) {
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buffer[BUFFER_SIZE];

    ssize_t len = recvfrom(sock, buffer, BUFFER_SIZE - 1, 0, (struct sockaddr *)&client_addr, &client_len);
    if (len == -1) {
      /* EINTR: sinal recebido (o `while` decide se continua).
       * ECONNREFUSED/EAGAIN: erros passageiros, basta tentar de novo.
       * Qualquer outro erro indica que o socket não é mais utilizável. */
      if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK || errno == ECONNREFUSED) {
        continue;
      }
      fprintf(stderr, "recvfrom failed: %s\n", strerror(errno));
      break;
    }

    buffer[len] = 0;

    /* Formato: "<comando> <id>\n[linhas...]" */
    char *buf_ptr = buffer;
    char *cmd = strsep(&buf_ptr, " ");
    char *id_str = strsep(&buf_ptr, "\n");

    if (id_str == NULL) {
      send_error(sock, &client_addr, client_len, "NO ID ARGUMENT AFTER COMMAND");
      continue;
    }

    uint32_t id;
    if (parse_id(id_str, &id) != 0) {
      send_error(sock, &client_addr, client_len, "INVALID ID");
      continue;
    }

    if (strcmp(cmd, "REGISTER") == 0) {
      /* Cada linha restante é um texto a registrar. Responde uma única vez:
       * REGISTERED se tudo foi guardado ou ERROR no primeiro problema. */
      bool failed = false;

      while (buf_ptr != NULL) {
        char *line = strsep(&buf_ptr, "\n");
        size_t line_len = strlen(line);
        if (line_len == 0) continue;

        if (line_len > PAYLOAD_SIZE - 1) {
          char reason[BUFFER_SIZE];
          snprintf(reason, sizeof(reason), "MAX PAYLOAD IS %d", PAYLOAD_SIZE - 1);
          send_error(sock, &client_addr, client_len, reason);
          failed = true;
          break;
        }

        Entry e = {.id = id};
        memcpy(e.payload, line, line_len + 1);  /* já sabemos que cabe (inclui o '\0') */

        if (entry_add(&entries, e) == -1) {
          fprintf(stderr, "Out of memory while registering an entry\n");
          send_error(sock, &client_addr, client_len, "SERVER OUT OF MEMORY");
          failed = true;
          break;
        }
      }

      if (!failed) {
        char reply[64];
        int reply_len = snprintf(reply, sizeof(reply), "REGISTERED %u\n", id);
        send_reply(sock, &client_addr, client_len, reply, (size_t)reply_len);
      }
    } else if (strcmp(cmd, "QUERY") == 0) {
      /* Monta "ENTRIES <id>\n" seguido de todos os textos daquele ID. */
      char reply[BUFFER_SIZE];
      size_t offset = (size_t)snprintf(reply, sizeof(reply), "ENTRIES %u\n", id);

      for (int i = 0; i < entries.len; i++) {
        Entry e = entries.items[i];
        if (e.id != id) continue;

        int written = snprintf(reply + offset, sizeof(reply) - offset, "%s\n", e.payload);
        /* Se a linha não couber inteira, para aqui: nunca envia além do buffer. */
        if (written < 0 || (size_t)written >= sizeof(reply) - offset) break;
        offset += (size_t)written;
      }

      send_reply(sock, &client_addr, client_len, reply, offset);
    } else {
      send_error(sock, &client_addr, client_len, "COMMAND DOES NOT EXIST");
    }
  }

  /* Chegou aqui por sinal (encerramento normal) ou por erro de recvfrom. */
  if (!running) {
    printf("\nShutting down\n");
    exit_code = EXIT_SUCCESS;
  }

  free(entries.items);
  close(sock);
  return exit_code;
}
