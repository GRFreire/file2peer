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

#include "stun.h"
#include "utils.h"

#include "common.h"

/* ========================================================================== */
/* Filas circulares e threads de rede (reader / writer)                       */
/* ========================================================================== */

/**
 * Thread writer: retira pacotes da fila de saída e os envia com sendto().
 * Dorme em sem_wait enquanto a fila está vazia. Erros passageiros de envio
 * apenas descartam o pacote (o protocolo retransmite); erros fatais são
 * registrados em ring->failed e encerram a thread.
 */
void *writer(void *arg) {
  ThreadArgs *args = (ThreadArgs *)arg;
  UDPRingBuffer *ring = args->ring;

  while (true) {
    /* sem_wait pode ser interrompido por um sinal: nesse caso, espera de novo. */
    while (sem_wait(&ring->sem) == -1) {
      if (errno != EINTR) {
        atomic_store(&ring->failed, errno);
        return NULL;
      }
    }

    int should_exit = atomic_load(&args->should_exit);
    int tail = atomic_load(&ring->tail);
    int head = atomic_load(&ring->head);

    /* Só encerra depois de esvaziar a fila. */
    if (should_exit && head == tail) {
      return NULL;
    }

    UDPPacket *p = &ring->data[tail];
    tail++;
    tail %= RING_BUFFER_CAP;

    if (sendto(args->sock, &p->buf, p->len, 0, p->addr, p->addrlen) == -1 && !is_transient_net_error(errno)) {
      atomic_store(&ring->failed, errno);
      return NULL;
    }

    atomic_store(&ring->tail, tail);
  }
}

/**
 * Coloca um pacote na fila de saída (o writer o enviará).
 * @return 0 em sucesso, -1 se a fila está cheia ou os argumentos são inválidos.
 *         Fila cheia não é falha fatal: os temporizadores do protocolo
 *         tentam enviar de novo mais tarde.
 */
int add_to_writer(UDPRingBuffer *ring, const void *buf, size_t len, const struct sockaddr *dest_addr,
                  socklen_t addrlen) {
  if (len > MAX_UDP_PACKET_SIZE || dest_addr == NULL) {
    return -1;
  }

  int head = atomic_load(&ring->head);
  int tail = atomic_load(&ring->tail);
  int new_head = (head + 1) % RING_BUFFER_CAP;
  if (new_head == tail) {
    return -1;
  }

  UDPPacket *p = &ring->data[head];
  p->len = len;
  memcpy(p->buf, buf, len);

  p->addrlen = addrlen;
  if (p->addrlen > sizeof(p->addr_storage)) p->addrlen = sizeof(p->addr_storage);
  memcpy(&p->addr_storage, dest_addr, p->addrlen);
  p->addr = (struct sockaddr *)&p->addr_storage;

  atomic_store(&ring->head, new_head);
  sem_post(&ring->sem);

  return 0;
}

/**
 * Thread reader: fica em recvfrom() e coloca cada datagrama na fila de
 * entrada. O semáforo conta as vagas livres: com a fila cheia, a thread dorme.
 * Erros passageiros são ignorados; erros fatais vão para ring->failed.
 */
void *reader(void *arg) {
  ThreadArgs *args = (ThreadArgs *)arg;
  UDPRingBuffer *ring = args->ring;

  while (true) {
    while (sem_wait(&ring->sem) == -1) {
      if (errno != EINTR) {
        atomic_store(&ring->failed, errno);
        return NULL;
      }
    }

    if (atomic_load(&args->should_exit)) {
      return NULL;
    }

    int head = atomic_load(&ring->head);
    int tail = atomic_load(&ring->tail);
    int new_head = (head + 1) % RING_BUFFER_CAP;
    /* O semáforo garante que sempre há vaga; se não houver, é bug do programa. */
    assert(new_head != tail && "semaphore should have handled full ring");
    (void)tail;  /* evita aviso de variável não usada quando assert é desligado */

    UDPPacket *p = &ring->data[head];
    p->addrlen = sizeof(p->addr_storage);
    ssize_t bytes_recv = recvfrom(args->sock, &p->buf, MAX_UDP_PACKET_SIZE, 0,
                                  (struct sockaddr *)&p->addr_storage, &p->addrlen);

    if (bytes_recv == (ssize_t)-1) {
      int err = errno;
      sem_post(&ring->sem);  /* devolve a vaga que não foi usada */
      if (is_transient_net_error(err)) {
        continue;
      }
      atomic_store(&ring->failed, err);
      return NULL;
    }

    p->len = (size_t)bytes_recv;
    p->addr = (struct sockaddr *)&p->addr_storage;

    atomic_store(&ring->head, new_head);
  }
}

/**
 * Retira o pacote mais antigo da fila de entrada (copiando-o para `packet`
 * quando não é NULL) e libera a vaga.
 * @return 0 se havia pacote, -1 se a fila está vazia.
 */
int take_from_reader(UDPRingBuffer *ring, UDPPacket *packet) {
  int tail = atomic_load(&ring->tail);
  int head = atomic_load(&ring->head);

  if (head == tail) {
    return -1;
  }

  if (packet != NULL) {
    *packet = ring->data[tail];
    packet->addr = (struct sockaddr *)&packet->addr_storage;
  }

  atomic_store(&ring->tail, (tail + 1) % RING_BUFFER_CAP);
  sem_post(&ring->sem);
  return 0;
}

/**
 * Como take_from_reader, mas não remove o pacote da fila.
 * @return 0 se havia pacote, -1 se a fila está vazia.
 */
int peek_from_reader(UDPRingBuffer *ring, UDPPacket *packet) {
  int tail = atomic_load(&ring->tail);
  int head = atomic_load(&ring->head);

  if (head == tail) {
    return -1;
  }

  if (packet != NULL) {
    *packet = ring->data[tail];
    packet->addr = (struct sockaddr *)&packet->addr_storage;
  }

  return 0;
}

/**
 * Compara dois endereços IPv4 (IP e porta).
 * @return 0 se forem iguais, 1 se forem diferentes ou inválidos.
 */
int addr_cmp(const struct sockaddr *a, const struct sockaddr *b) {
  if (a == NULL || b == NULL) return 1;

  if (a->sa_family != b->sa_family) return 1;
  if (a->sa_family != AF_INET) return 1;

  const struct sockaddr_in *a_in = (const struct sockaddr_in *)a;
  const struct sockaddr_in *b_in = (const struct sockaddr_in *)b;

  if (a_in->sin_addr.s_addr != b_in->sin_addr.s_addr) return 1;
  if (a_in->sin_port != b_in->sin_port) return 1;

  return 0;
}

/**
 * Verifica se alguma thread de rede registrou uma falha fatal.
 * @return true (e imprime o motivo em stderr) se reader ou writer falhou.
 */
bool network_thread_failed(UDPRingBuffer *reader_ring, UDPRingBuffer *writer_ring) {
  const char *which = "reader";
  int err = atomic_load(&reader_ring->failed);

  if (err == 0) {
    which = "writer";
    err = atomic_load(&writer_ring->failed);
  }
  if (err == 0) return false;

  fprintf(stderr, "Network %s thread failed: %s\n", which, strerror(err));
  return true;
}

/**
 * Envia um pacote de controle (só cabeçalho) do tipo indicado.
 * @return 0 em sucesso, -1 se a fila de saída está cheia.
 */
int send_ack(UDPRingBuffer *packet_ring, Peer peer, PacketType type, uint32_t id, uint32_t ack_id) {
  PacketHeader p = {
      .type = (uint8_t)type,
      ._reserved = 0,
      .checksum = 0,
      .id = id,
      .ack_id = ack_id,
  };

  return add_to_writer(packet_ring, &p, sizeof(p), peer.addr, peer.addrlen);
}

/** Envia um CONNECT. @return 0 em sucesso, -1 se a fila de saída está cheia. */
int send_connect(UDPRingBuffer *packet_ring, Peer peer, uint32_t id, uint32_t ack_id) {
  return send_ack(packet_ring, peer, PACK_TYP_CONNECT, id, ack_id);
}

/** Envia um CLOSE. @return 0 em sucesso, -1 se a fila de saída está cheia. */
int send_close(UDPRingBuffer *packet_ring, Peer peer, uint32_t id, uint32_t ack_id) {
  return send_ack(packet_ring, peer, PACK_TYP_CLOSE, id, ack_id);
}

/**
 * Envia um DATA com `length` bytes do arquivo que começam em `offset`.
 * @return 0 em sucesso, -1 se a fila está cheia ou `length` é grande demais.
 */
int send_data(UDPRingBuffer *packet_ring, Peer peer, uint32_t offset, uint32_t length, const void *data) {
  if (length > MAX_PACKET_PAYLOAD_SIZE) {
    return -1;
  }

  uint8_t buffer[MAX_PACKET_PAYLOAD_SIZE + sizeof(PacketHeader)] = {0};
  PacketHeader p = {
      .type = PACK_TYP_DATA,
      ._reserved = 0,
      .checksum = 0,
      .offset = offset,
      .length = length,
  };

  memcpy(&buffer[0], &p, sizeof(p));
  memcpy(&buffer[sizeof(p)], data, length);

  return add_to_writer(packet_ring, buffer, sizeof(PacketHeader) + length, peer.addr, peer.addrlen);
}

/** Envia um DATA_ACK para o DATA com o mesmo offset. @return 0 ou -1 (fila cheia). */
int send_data_ack(UDPRingBuffer *packet_ring, Peer peer, uint32_t offset, uint32_t length) {
  PacketHeader p = {
      .type = PACK_TYP_DATA_ACK,
      ._reserved = 0,
      .checksum = 0,
      .offset = offset,
      .length = length,
  };

  return add_to_writer(packet_ring, &p, sizeof(p), peer.addr, peer.addrlen);
}

/**
 * Interpreta um datagrama recebido.
 * @param data se não for NULL, recebe um ponteiro para o payload (logo após o cabeçalho).
 * @return o cabeçalho; type == PACK_INVALID se o pacote for curto demais ou
 *         se um DATA declarar mais bytes do que realmente chegaram.
 */
PacketHeader parse_packet(const void *packet, size_t packet_len, const void **data) {
  PacketHeader ph = {0};

  if (packet_len < sizeof(PacketHeader)) {
    fprintf(stderr, "Received malformed packet\n");
    ph.type = PACK_INVALID;
    return ph;
  }

  memcpy(&ph, packet, sizeof(PacketHeader));

  if (ph.type == PACK_TYP_DATA) {
    if (ph.length + sizeof(PacketHeader) > packet_len) {
      fprintf(stderr, "Data packet incomplete (not enough data)\n");
      ph.type = PACK_INVALID;
      return ph;
    }
  }

  if (data != NULL) {
    *data = (const uint8_t *)packet + sizeof(PacketHeader);
  }
  return ph;
}

/* ========================================================================== */
/* Candidatos de peer e cliente do ERS                                        */
/* ========================================================================== */

/** Libera a memória dos candidatos. */
void peer_list_free(PeerList *list) {
  for (int i = 0; i < list->len; i++) {
    freeaddrinfo(list->infos[i]);
  }
  list->len = 0;
}

/** Libera os recursos da sessão (pode ser chamada mais de uma vez). */
void ers_session_free(ErsSession *ers) {
  if (ers->server != NULL) {
    freeaddrinfo(ers->server);
    ers->server = NULL;
  }
}

/** Avisa que uma mensagem do ERS não coube no buffer. @return sempre -1. */
int ers_request_too_long(void) {
  fprintf(stderr, "ERS request does not fit in its buffer\n");
  return -1;
}

/**
 * Monta as mensagens REGISTER, REGISTERED esperada e QUERY.
 * @return 0 em sucesso, -1 em falha (o motivo é impresso em stderr).
 */
int ers_build_requests(ErsSession *ers, const Endpoint *my_endpoints, int my_endpoints_len,
                              int ers_id) {
  /* REGISTER <id>\n<ip:porta>\n<ip:porta>\n... */
  size_t offset = 0;
  int written = snprintf(ers->register_req, sizeof(ers->register_req), "REGISTER %d\n", ers_id);
  if (!snprintf_ok(written, sizeof(ers->register_req))) return ers_request_too_long();
  offset += (size_t)written;

  for (int i = 0; i < my_endpoints_len; i++) {
    struct in_addr ip;
    ip.s_addr = htonl(my_endpoints[i].addr);
    if (inet_ntop(AF_INET, &ip, ers->ip_string[i], sizeof(ers->ip_string[i])) == NULL) {
      fprintf(stderr, "Could not format local address: %s\n", strerror(errno));
      return -1;
    }

    written = snprintf(ers->register_req + offset, sizeof(ers->register_req) - offset, "%s:%u\n",
                       ers->ip_string[i], my_endpoints[i].port);
    if (!snprintf_ok(written, sizeof(ers->register_req) - offset)) return ers_request_too_long();
    offset += (size_t)written;
  }
  ers->register_req_len = offset;

  written = snprintf(ers->expected_response, sizeof(ers->expected_response), "REGISTERED %d\n", ers_id);
  if (!snprintf_ok(written, sizeof(ers->expected_response))) return ers_request_too_long();
  ers->expected_response_len = (size_t)written;

  written = snprintf(ers->query_req, sizeof(ers->query_req), "QUERY %d\n", ers_id);
  if (!snprintf_ok(written, sizeof(ers->query_req))) return ers_request_too_long();
  ers->query_req_len = (size_t)written;

  return 0;
}

/**
 * Resolve o endereço do ERS (ERS_ADDR/ERS_PORT, padrão ers.grfreire.com:54321)
 * e monta as mensagens REGISTER e QUERY com os nossos candidatos.
 * @return 0 em sucesso, -1 em falha (o motivo é impresso em stderr).
 */
int ers_session_setup(ErsSession *ers, const Endpoint *my_endpoints, int my_endpoints_len, int ers_id) {
  memset(ers, 0, sizeof(*ers));
  ers->id = ers_id;

  if (my_endpoints_len > PEERS_CAP) {
    fprintf(stderr, "Too many local endpoints (%d)\n", my_endpoints_len);
    return -1;
  }

  const char *ers_addr = "ers.grfreire.com";
  const char *ers_addr_env = getenv("ERS_ADDR");
  if (ers_addr_env != NULL) ers_addr = ers_addr_env;

  const char *ers_port = "54321";
  const char *ers_port_env = getenv("ERS_PORT");
  if (ers_port_env != NULL) ers_port = ers_port_env;

  int ret = getaddrinfo(ers_addr, ers_port, &addr_hints, &ers->server);
  if (ret != 0) {
    fprintf(stderr, "Could not resolve ERS server %s:%s (%s)\n", ers_addr, ers_port, gai_strerror(ret));
    ers->server = NULL;
    return -1;
  }

  if (ers_build_requests(ers, my_endpoints, my_endpoints_len, ers_id) != 0) {
    ers_session_free(ers);
    return -1;
  }
  return 0;
}

/** Diz se o pacote é uma resposta de erro do ERS ("ERROR\n<motivo>\n"). */
bool ers_reply_is_error(const UDPPacket *packet) {
  return packet->len >= 5 && memcmp(packet->buf, "ERROR", 5) == 0;
}

/** Imprime em stderr o texto de uma resposta de erro do ERS. */
void ers_report_error(const UDPPacket *packet) {
  fprintf(stderr, "ERS returned an error:\n%.*s", (int)packet->len, (const char *)packet->buf);
}

/**
 * Interpreta uma resposta "ENTRIES <id>\n<ip:porta>\n..." do ERS e acrescenta
 * à lista os candidatos que não são nossos. Linhas inválidas são ignoradas.
 * Modifica o conteúdo de `packet->buf` (o texto é cortado com strsep).
 * @return quantos candidatos novos foram acrescentados (0 se a resposta não
 *         era um ENTRIES válido para o nosso ID).
 */
int ers_collect_peers(const ErsSession *ers, UDPPacket *packet, const Endpoint *my_endpoints,
                      int my_endpoints_len, PeerList *list) {
  char *buf_ptr = (char *)packet->buf;

  /* Garante o '\0' final para poder usar funções de string. */
  size_t last = packet->len;
  if (last > MAX_UDP_PACKET_SIZE - 1) last = MAX_UDP_PACKET_SIZE - 1;
  buf_ptr[last] = 0;

  char *reply = strsep(&buf_ptr, " ");
  if (strcmp(reply, "ENTRIES") != 0) return 0;

  char *id_str = strsep(&buf_ptr, "\n");
  long reply_id;
  if (id_str == NULL || parse_long(id_str, 0, INT_MAX, &reply_id) != 0 || reply_id != ers->id) {
    return 0;
  }

  int added = 0;
  while (buf_ptr != NULL && buf_ptr[0] != 0 && list->len < PEERS_CAP) {
    char *payload = strsep(&buf_ptr, "\n");

    char *reply_ip_str = strsep(&payload, ":");
    char *reply_port_str = payload;
    long reply_port;
    if (reply_port_str == NULL || parse_long(reply_port_str, 1, 65535, &reply_port) != 0) {
      continue;
    }

    /* O ERS devolve todos os candidatos do ID, inclusive os nossos: ignora-os. */
    bool is_self = false;
    for (int i = 0; i < my_endpoints_len; i++) {
      if (strcmp(reply_ip_str, ers->ip_string[i]) == 0 && reply_port == my_endpoints[i].port) {
        is_self = true;
        break;
      }
    }
    if (is_self) continue;

    struct addrinfo *peer_addr = NULL;
    int ret = getaddrinfo(reply_ip_str, reply_port_str, &addr_hints, &peer_addr);
    if (ret != 0) {
      fprintf(stderr, "Could not resolve peer address %s:%s (%s)\n", reply_ip_str, reply_port_str,
              gai_strerror(ret));
      continue;
    }

    list->infos[list->len] = peer_addr;
    list->peers[list->len] = (Peer){
        .addr = peer_addr->ai_addr,
        .addrlen = peer_addr->ai_addrlen,
    };
    list->len++;
    added++;
  }

  return added;
}
