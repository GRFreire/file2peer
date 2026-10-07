#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "utils.h"
#include "common.h"
#include "sender.h"
#include "receiver.h"
#include "stun.h"

#define LINE_BUF_SIZE 100

/** Imprime a forma de uso do programa em stderr. */
void print_usage(const char *program) {
  fprintf(stderr, "Usage: %s <send|receive> FILE\n", program);
}

/**
 * Obtém o ID de sessão: o remetente gera um aleatório e o mostra; o
 * destinatário lê o ID digitado pelo usuário.
 * @return 0 em sucesso, -1 se a leitura ou o valor digitado for inválido.
 */
int get_session_id(bool cmd_send, int *out_id) {
  if (cmd_send) {
    srand((unsigned int)time(NULL));
    *out_id = rand();
    printf("ERS id: %d\n", *out_id);
    fflush(stdout);  /* garante que o ID apareça mesmo com a saída redirecionada */
    return 0;
  }

  printf("What is the ERS id? ");
  fflush(stdout);

  char line[LINE_BUF_SIZE];
  if (fgets(line, sizeof(line), stdin) == NULL) {
    fprintf(stderr, "\nCould not read the ERS id from stdin\n");
    return -1;
  }

  long value;
  if (parse_long(line, 0, INT_MAX, &value) != 0) {
    fprintf(stderr, "Invalid ERS id (expected a non-negative integer)\n");
    return -1;
  }

  *out_id = (int)value;
  return 0;
}

/** Filas, semáforos e threads de rede. network_stop desfaz só o que já foi criado. */
typedef struct {
  UDPRingBuffer writer_ring;
  UDPRingBuffer reader_ring;
  ThreadArgs writer_args;
  ThreadArgs reader_args;
  pthread_t writer_thread;
  pthread_t reader_thread;
  bool writer_sem_ready;
  bool reader_sem_ready;
  bool writer_started;
  bool reader_started;
} Network;

/**
 * Para as threads e libera tudo o que network_start chegou a criar. É segura
 * com uma Network só parcialmente iniciada e pode ser chamada mais de uma vez.
 */
void network_stop(Network *net) {
  /* O reader fica bloqueado em recvfrom(), então é cancelado; o writer é avisado
   * por should_exit + sem_post e termina depois de esvaziar a fila. */
  if (net->reader_started) {
    atomic_store(&net->reader_args.should_exit, 1);
    pthread_cancel(net->reader_thread);
    pthread_join(net->reader_thread, NULL);
    net->reader_started = false;
  }
  if (net->writer_started) {
    atomic_store(&net->writer_args.should_exit, 1);
    sem_post(&net->writer_ring.sem);
    pthread_join(net->writer_thread, NULL);
    net->writer_started = false;
  }

  if (net->writer_sem_ready) sem_destroy(&net->writer_ring.sem);
  if (net->reader_sem_ready) sem_destroy(&net->reader_ring.sem);
  net->writer_sem_ready = false;
  net->reader_sem_ready = false;

  free(net->writer_ring.data);
  free(net->reader_ring.data);
  net->writer_ring.data = NULL;
  net->reader_ring.data = NULL;
}

/**
 * Aloca as duas filas e inicia seus semáforos.
 * @return 0 em sucesso, -1 em falha (quem chama deve usar network_stop).
 */
static int network_init_queues(Network *net) {
  /* Fila de saída: o semáforo conta pacotes prontos (começa em 0). */
  net->writer_ring.data = malloc(sizeof(UDPPacket) * RING_BUFFER_CAP);
  if (net->writer_ring.data == NULL) {
    fprintf(stderr, "Out of memory allocating the writer queue\n");
    return -1;
  }
  if (sem_init(&net->writer_ring.sem, 0, 0) == -1) {
    fprintf(stderr, "Could not initialize the writer semaphore: %s\n", strerror(errno));
    return -1;
  }
  net->writer_sem_ready = true;

  /* Fila de entrada: o semáforo conta vagas livres (começa cheio). */
  net->reader_ring.data = malloc(sizeof(UDPPacket) * RING_BUFFER_CAP);
  if (net->reader_ring.data == NULL) {
    fprintf(stderr, "Out of memory allocating the reader queue\n");
    return -1;
  }
  if (sem_init(&net->reader_ring.sem, 0, RING_BUFFER_CAP - 1) == -1) {
    fprintf(stderr, "Could not initialize the reader semaphore: %s\n", strerror(errno));
    return -1;
  }
  net->reader_sem_ready = true;

  return 0;
}

/**
 * Inicia as threads writer e reader.
 * @return 0 em sucesso, -1 em falha (quem chama deve usar network_stop).
 */
static int network_start_threads(Network *net) {
  /* pthread_create devolve o código de erro (não usa errno). */
  int rc = pthread_create(&net->writer_thread, NULL, writer, &net->writer_args);
  if (rc != 0) {
    fprintf(stderr, "Could not start the writer thread: %s\n", strerror(rc));
    return -1;
  }
  net->writer_started = true;

  rc = pthread_create(&net->reader_thread, NULL, reader, &net->reader_args);
  if (rc != 0) {
    fprintf(stderr, "Could not start the reader thread: %s\n", strerror(rc));
    return -1;
  }
  net->reader_started = true;

  return 0;
}

/**
 * Prepara as filas e inicia as threads de rede sobre o socket.
 * @param net deve estar zerada ({0}).
 * @return 0 em sucesso, -1 em falha (nada fica alocado nem rodando).
 */
int network_start(Network *net, int sock) {
  net->writer_args.sock = sock;
  net->writer_args.ring = &net->writer_ring;
  net->reader_args.sock = sock;
  net->reader_args.ring = &net->reader_ring;

  if (network_init_queues(net) != 0 || network_start_threads(net) != 0) {
    network_stop(net);
    return -1;
  }
  return 0;
}

/**
 * Descobre os candidatos de endereço, obtém o ID de sessão, inicia a rede e
 * executa o protocolo.
 * @return 0 se a transferência terminou bem, -1 em falha.
 */
int run_transfer(int sock, bool cmd_send, const char *filename) {
  Endpoint my_endpoints[3];
  int my_endpoints_len = 0;
  int id = 0;

  /* Candidato 1: endereço público (STUN). Se falhar, seguimos só com os locais. */
  Endpoint public_endpoint;
  if (get_socket_public_endpoint(sock, &public_endpoint) == 0) {
    my_endpoints[my_endpoints_len++] = public_endpoint;
  } else {
    printf("STUN failed, using local endpoints only.\n");
  }

  /* Candidatos 2 e 3: loopback (mesma máquina) e LAN (mesma rede local). */
  Endpoint loopback_endpoint;
  if (get_socket_loopback_endpoint(sock, &loopback_endpoint) == 0) {
    loopback_endpoint.addr = INADDR_LOOPBACK;
    my_endpoints[my_endpoints_len++] = loopback_endpoint;

    uint32_t lan_ip;
    if (get_lan_ip(&lan_ip) == 0) {
      Endpoint local_endpoint = loopback_endpoint;
      local_endpoint.addr = lan_ip;
      my_endpoints[my_endpoints_len++] = local_endpoint;
    } else {
      printf("No LAN address found, skipping LAN endpoint.\n");
    }
  }

  if (my_endpoints_len == 0) {
    fprintf(stderr, "Could not get any endpoint\n");
    return -1;
  }

  if (get_session_id(cmd_send, &id) != 0) return -1;

  Network net = {0};
  if (network_start(&net, sock) != 0) return -1;

  /* Toda a lógica do protocolo roda na thread principal. */
  int run_result;
  if (cmd_send) {
    run_result = sender(&net.reader_ring, &net.writer_ring, my_endpoints, my_endpoints_len, filename, id);
  } else {
    run_result = receiver(&net.reader_ring, &net.writer_ring, my_endpoints, my_endpoints_len, filename, id);
  }

  network_stop(&net);
  return run_result;
}

int main(int argc, char **argv) {
  if (argc < 3) {
    print_usage(argv[0]);
    return EXIT_FAILURE;
  }

  bool cmd_send = false;
  if (strcmp("send", argv[1]) == 0) {
    cmd_send = true;
  } else if (strcmp("receive", argv[1]) == 0) {
    cmd_send = false;
  } else {
    print_usage(argv[0]);
    return EXIT_FAILURE;
  }

  const char *filename = argv[2];

  /* Falha cedo: não adianta registrar no ERS e esperar o peer se o arquivo
   * a enviar não existe ou não pode ser lido. */
  if (cmd_send && access(filename, R_OK) == -1) {
    fprintf(stderr, "Cannot read '%s': %s\n", filename, strerror(errno));
    return EXIT_FAILURE;
  }

  /* Um único socket UDP: o NAT mapeia a porta local deste socket. */
  int sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock == -1) {
    fprintf(stderr, "Could not create UDP socket: %s\n", strerror(errno));
    return EXIT_FAILURE;
  }

  int run_result = run_transfer(sock, cmd_send, filename);

  close(sock);
  return run_result == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
