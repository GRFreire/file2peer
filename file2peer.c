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

/* ========================================================================== */
/* Utilitários                                                                */
/* ========================================================================== */

#define NANOS_PER_SEC (1000 * 1000 * 1000)

/**
 * Lê o relógio monotônico (não é afetado por ajustes da hora do sistema).
 * @param out_seconds recebe o tempo em segundos, com origem não especificada.
 * @return 0 em sucesso, -1 em falha (errno é preenchido por clock_gettime).
 */
int seconds_since_unspecified_epoch(double *out_seconds) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) == -1) {
    return -1;
  }

  *out_seconds = (double)ts.tv_sec + (double)ts.tv_nsec / NANOS_PER_SEC;
  return 0;
}

/**
 * Diz se um erro de rede é passageiro. Em UDP isso não precisa derrubar o
 * programa: o pacote perdido é recuperado pela retransmissão do protocolo.
 */
bool is_transient_net_error(int err) {
  return err == EINTR || err == EAGAIN || err == EWOULDBLOCK || err == ENOBUFS || err == ENETDOWN ||
         err == ENETUNREACH || err == EHOSTUNREACH || err == ECONNREFUSED || err == ECONNRESET ||
         err == EPERM;
}

/**
 * Converte um texto em inteiro validando o texto inteiro e o intervalo.
 * Espaços no começo e no fim são aceitos.
 * @return 0 em sucesso, -1 se o texto não for um número em [min, max].
 */
int parse_long(const char *str, long min, long max, long *out) {
  char *end = NULL;
  errno = 0;
  long value = strtol(str, &end, 10);
  if (end == str || errno == ERANGE) return -1;

  while (isspace((unsigned char)*end)) end++;
  if (*end != '\0') return -1;
  if (value < min || value > max) return -1;

  *out = value;
  return 0;
}

/** Diz se o retorno de snprintf indica que o texto coube inteiro no buffer. */
bool snprintf_ok(int written, size_t buf_size) {
  return written >= 0 && (size_t)written < buf_size;
}

/* ========================================================================== */
/* STUN (RFC 5389): descobre o endereço público do socket                     */
/* ========================================================================== */

#define STUN_MAGIC_COOKIE 0x2112A442
#define STUN_BINDING_REQUEST 0x0001
#define STUN_BINDING_SUCCESS_RESPONSE 0x0101
#define STUN_XOR_MAPPED_ADDRESS 0x0020
#define STUN_IPV4_FAMILY 0x01
#define STUN_BUFFER_SIZE 1500

/** Cabeçalho de 20 bytes de toda mensagem STUN. */
typedef struct {
  uint16_t type;
  uint16_t length;
  uint32_t cookie;
  uint8_t transaction_id[12];
} stun_header;
static_assert(sizeof(stun_header) == 20, "stun header struct wrongly packed");

/** Cabeçalho de um atributo STUN (formato type-length-value). */
typedef struct {
  uint16_t type;
  uint16_t length;
} stun_tlv;
static_assert(sizeof(stun_tlv) == 4, "stun tlv struct wrongly packed");

/** Valor do atributo XOR-MAPPED-ADDRESS (IPv4). */
typedef struct {
  uint8_t zeros;
  uint8_t family;
  uint16_t xor_port;
  uint32_t xor_addr;
} stun_xor_mapped_addr;
static_assert(sizeof(stun_xor_mapped_addr) == 8, "stun xor mapped addr struct wrongly packed");

/** Endereço IPv4 + porta, ambos em ordem de bytes do host. */
typedef struct {
  uint32_t addr;
  uint16_t port;
} Endpoint;

/** Dicas para getaddrinfo: apenas IPv4, UDP e porta numérica. */
struct addrinfo addr_hints = {.ai_family = AF_INET, .ai_socktype = SOCK_DGRAM, .ai_flags = AI_NUMERICSERV};

/** Imprime um Endpoint (função de depuração). */
void print_endpoint(Endpoint endpoint) {
  struct in_addr ip;
  ip.s_addr = htonl(endpoint.addr);

  char ip_string[INET_ADDRSTRLEN];
  if (inet_ntop(AF_INET, &ip, ip_string, sizeof(ip_string)) == NULL) {
    fprintf(stderr, "Could not format endpoint address: %s\n", strerror(errno));
    return;
  }

  printf("Endpoint: %s:%u\n", ip_string, endpoint.port);
}

/** Imprime um struct sockaddr com um rótulo (função de depuração). */
void print_addr(const char *label, const struct sockaddr *addr) {
  if (addr == NULL) {
    printf("%s: (null)\n", label);
    return;
  }

  if (addr->sa_family == AF_INET) {
    const struct sockaddr_in *in = (const struct sockaddr_in *)addr;
    char ip[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &in->sin_addr, ip, sizeof(ip)) == NULL) {
      printf("%s: (invalid address)\n", label);
      return;
    }
    printf("%s: %s:%u\n", label, ip, ntohs(in->sin_port));
  } else {
    printf("%s: unsupported family %d\n", label, addr->sa_family);
  }
}

#define STUN_RETRY_INTERVAL 0.5  /* segundos entre Binding Requests */
#define STUN_MAX_TRY_TIME 2      /* segundos até desistir do STUN */

/**
 * Troca de mensagens com o servidor STUN já resolvido: reenvia o Binding Request
 * até chegar a resposta ou estourar STUN_MAX_TRY_TIME.
 * @return 0 em sucesso, -1 em falha (o motivo é impresso em stderr).
 */
static int stun_exchange(int sock, const struct addrinfo *stun_server, const char *stun_addr,
                         const char *stun_port, Endpoint *out_endpoint) {
  int result = -1;

  stun_header req_header = {
      .type = htons(STUN_BINDING_REQUEST),
      .length = htons(0),
      .cookie = htonl(STUN_MAGIC_COOKIE),
      .transaction_id = {0},
  };
  uint8_t response[STUN_BUFFER_SIZE];
  double started_trying = 0;
  double last_sent = 0;

  /* O transaction id aleatório liga cada resposta ao nosso pedido. */
  if (getrandom(req_header.transaction_id, sizeof(req_header.transaction_id), 0) !=
      (ssize_t)sizeof(req_header.transaction_id)) {
    fprintf(stderr, "STUN: could not generate transaction id: %s\n", strerror(errno));
    return -1;
  }

  if (seconds_since_unspecified_epoch(&started_trying) != 0) {
    fprintf(stderr, "STUN: could not read the clock: %s\n", strerror(errno));
    return -1;
  }

  while (true) {
    double now;
    if (seconds_since_unspecified_epoch(&now) != 0) {
      fprintf(stderr, "STUN: could not read the clock: %s\n", strerror(errno));
      break;
    }

    /* (Re)envia o pedido a cada STUN_RETRY_INTERVAL até chegar a resposta. */
    if ((now - last_sent) > STUN_RETRY_INTERVAL) {
      ssize_t sent = sendto(sock, &req_header, sizeof(req_header), 0, stun_server->ai_addr,
                            stun_server->ai_addrlen);
      if (sent != -1) {
        last_sent = now;
      } else if (!is_transient_net_error(errno)) {
        fprintf(stderr, "STUN: sendto failed: %s\n", strerror(errno));
        break;
      }
    }

    if ((now - started_trying) > STUN_MAX_TRY_TIME) {
      fprintf(stderr, "STUN: no response from %s:%s after %d s\n", stun_addr, stun_port, STUN_MAX_TRY_TIME);
      break;
    }

    ssize_t bytes_recv = recvfrom(sock, &response, sizeof(response), MSG_DONTWAIT, NULL, NULL);
    if (bytes_recv == -1) {
      /* Sem dados ainda (EAGAIN) ou erro passageiro: espera 1 ms e tenta de novo.
       * Qualquer outro erro significa que o socket não serve mais. */
      if (!is_transient_net_error(errno)) {
        fprintf(stderr, "STUN: recvfrom failed: %s\n", strerror(errno));
        break;
      }
      struct timespec ts = {.tv_sec = 0, .tv_nsec = 1000 * 1000};
      nanosleep(&ts, NULL);  /* se for interrompida, o laço apenas repete */
    } else if ((size_t)bytes_recv < sizeof(stun_header)) {
      /* Pacote curto demais para ter cabeçalho STUN: ignora. */
    } else {
      size_t offset = 0;
      stun_header res_header;
      memcpy(&res_header, &response[offset], sizeof(res_header));
      offset += sizeof(stun_header);

      res_header.type = ntohs(res_header.type);
      res_header.length = ntohs(res_header.length);
      res_header.cookie = ntohl(res_header.cookie);

      /* Descarta tudo o que não for a resposta de sucesso ao nosso pedido. */
      if (res_header.cookie != STUN_MAGIC_COOKIE) continue;
      if (res_header.type != STUN_BINDING_SUCCESS_RESPONSE) continue;
      if (memcmp(req_header.transaction_id, res_header.transaction_id,
                 sizeof(req_header.transaction_id)) != 0) {
        continue;
      }
      if ((size_t)bytes_recv < res_header.length + sizeof(stun_header)) continue;

      /* Percorre os atributos TLV procurando o XOR-MAPPED-ADDRESS. */
      Endpoint endpoint = {0};
      bool found = false;
      while (offset + sizeof(stun_tlv) <= (size_t)res_header.length + sizeof(stun_header)) {
        stun_tlv tlv;
        memcpy(&tlv, &response[offset], sizeof(tlv));
        offset += sizeof(stun_tlv);

        tlv.type = ntohs(tlv.type);
        tlv.length = ntohs(tlv.length);

        /* Atributos são sempre alinhados em 4 bytes. */
        size_t next_attr_offset = ((size_t)tlv.length + 3) & ~(size_t)3;

        /* Atributo maior do que os dados recebidos: resposta truncada. */
        if (offset + tlv.length > (size_t)res_header.length + sizeof(stun_header)) break;

        /* Outro atributo, ou XOR-MAPPED-ADDRESS inválido: pula. */
        if (tlv.type != STUN_XOR_MAPPED_ADDRESS || tlv.length < sizeof(stun_xor_mapped_addr)) {
          offset += next_attr_offset;
          continue;
        }

        stun_xor_mapped_addr addr;
        memcpy(&addr, &response[offset], sizeof(addr));
        offset += next_attr_offset;

        if (addr.family != STUN_IPV4_FAMILY) continue;  /* só IPv4 */

        /* O servidor aplica XOR com o magic cookie; desfazemos aqui. */
        endpoint.port = (uint16_t)(ntohs(addr.xor_port) ^ (STUN_MAGIC_COOKIE >> 16));
        endpoint.addr = ntohl(addr.xor_addr) ^ STUN_MAGIC_COOKIE;
        found = true;
        break;
      }

      if (!found) continue;

      *out_endpoint = endpoint;
      result = 0;
      break;
    }
  }

  return result;
}

/**
 * Descobre o IP e a porta públicos do socket enviando um Binding Request ao
 * servidor STUN pelo próprio socket (o NAT mapeia a porta local do socket).
 * O servidor vem de STUN_ADDR/STUN_PORT (padrão: stun.l.google.com:19302).
 *
 * @param sock         socket UDP que será usado na transferência.
 * @param out_endpoint recebe o endereço público em caso de sucesso.
 * @return 0 em sucesso, -1 em falha (o motivo é impresso em stderr).
 */
int get_socket_public_endpoint(int sock, Endpoint *out_endpoint) {
  struct addrinfo *stun_server = NULL;

  const char *stun_addr = "stun.l.google.com";
  const char *stun_addr_env = getenv("STUN_ADDR");
  if (stun_addr_env != NULL) stun_addr = stun_addr_env;

  const char *stun_port = "19302";
  const char *stun_port_env = getenv("STUN_PORT");
  if (stun_port_env != NULL) stun_port = stun_port_env;

  int ret = getaddrinfo(stun_addr, stun_port, &addr_hints, &stun_server);
  if (ret != 0) {
    fprintf(stderr, "STUN: could not resolve %s:%s (%s)\n", stun_addr, stun_port, gai_strerror(ret));
    return -1;
  }

  int result = stun_exchange(sock, stun_server, stun_addr, stun_port, out_endpoint);
  freeaddrinfo(stun_server);
  return result;
}

/**
 * Descobre a porta local do socket (fazendo bind em porta livre se ainda não
 * houver) para montar o candidato de loopback. O campo addr não é preenchido
 * com 127.0.0.1 aqui: quem chama define o IP.
 * @return 0 em sucesso, -1 em falha.
 */
int get_socket_loopback_endpoint(int sock, Endpoint *out_endpoint) {
  struct sockaddr_in addr;
  socklen_t addr_len = sizeof(addr);

  if (getsockname(sock, (struct sockaddr *)&addr, &addr_len) == -1) {
    fprintf(stderr, "Could not get local socket endpoint: %s\n", strerror(errno));
    return -1;
  }

  /* Porta 0: o socket ainda não foi ligado (ex.: o STUN falhou antes do envio). */
  if (addr.sin_port == 0) {
    if (bind(sock, (struct sockaddr *)&addr, addr_len) == -1) {
      fprintf(stderr, "Could not bind to any port: %s\n", strerror(errno));
      return -1;
    }

    if (getsockname(sock, (struct sockaddr *)&addr, &addr_len) == -1) {
      fprintf(stderr, "Could not get local socket endpoint: %s\n", strerror(errno));
      return -1;
    }
  }

  out_endpoint->port = ntohs(addr.sin_port);
  out_endpoint->addr = ntohl(addr.sin_addr.s_addr);
  return 0;
}

/**
 * Descobre o IP da interface de rede local usada para sair para a internet.
 * Usa o truque de "conectar" um socket UDP a um endereço de documentação
 * (192.0.2.1): nenhum pacote é enviado, mas o kernel escolhe a interface e
 * getsockname revela o IP dela.
 * @param out_addr recebe o IP em ordem de bytes do host.
 * @return 0 em sucesso, -1 em falha (ex.: sem rota de rede).
 */
int get_lan_ip(uint32_t *out_addr) {
  int tmp_sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (tmp_sock == -1) return -1;

  struct sockaddr_in dummy_addr = {.sin_family = AF_INET, .sin_port = htons(1)};
  if (inet_pton(AF_INET, "192.0.2.1", &dummy_addr.sin_addr) != 1) {
    close(tmp_sock);
    return -1;
  }

  if (connect(tmp_sock, (struct sockaddr *)&dummy_addr, sizeof(dummy_addr)) == -1) {
    close(tmp_sock);
    return -1;
  }

  struct sockaddr_in my_addr = {0};
  socklen_t len = sizeof(my_addr);
  if (getsockname(tmp_sock, (struct sockaddr *)&my_addr, &len) == -1) {
    close(tmp_sock);
    return -1;
  }

  close(tmp_sock);

  *out_addr = ntohl(my_addr.sin_addr.s_addr);
  return 0;
}

/* ========================================================================== */
/* Filas circulares e threads de rede (reader / writer)                       */
/* ========================================================================== */

#define MAX_UDP_PACKET_SIZE 1500

/** Um datagrama UDP junto com o endereço do remetente (ou do destinatário). */
typedef struct {
  size_t len;
  struct sockaddr *addr;  /* aponta para addr_storage */
  socklen_t addrlen;
  struct sockaddr_storage addr_storage;
  uint8_t buf[MAX_UDP_PACKET_SIZE];
} UDPPacket;

#define RING_BUFFER_CAP 1024

/**
 * Fila circular com um produtor e um consumidor (dispensa mutex).
 * `failed` guarda o errno de uma falha fatal da thread de rede associada
 * (0 = tudo certo), para a thread principal perceber e encerrar com erro.
 */
typedef struct {
  _Atomic int head;
  _Atomic int tail;
  _Atomic int failed;
  UDPPacket *data;
  sem_t sem;
} UDPRingBuffer;

/** Argumentos das threads reader e writer. */
typedef struct {
  int sock;
  _Atomic int should_exit;
  UDPRingBuffer *ring;
} ThreadArgs;

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

/* ========================================================================== */
/* Formato dos pacotes do protocolo                                           */
/* ========================================================================== */

#define LINE_BUF_SIZE 100

/** Tipos de pacote (campo `type` do cabeçalho). */
typedef enum {
  PACK_RESERVED = 0,
  PACK_INVALID,
  PACK_TYP_CONNECT,
  PACK_TYP_CONNECT_ACK,
  PACK_TYP_CLOSE,
  PACK_TYP_CLOSE_ACK,
  PACK_TYP_DATA,
  PACK_TYP_DATA_ACK,
} PacketType;

/**
 * Cabeçalho fixo de 12 bytes de todo pacote.
 * Em DATA/DATA_ACK, offset e length dizem qual trecho do arquivo o pacote
 * carrega; nos pacotes de controle esses campos não são usados.
 */
typedef struct {
  uint8_t type;
  uint8_t _reserved;
  uint16_t checksum;
  union {
    uint32_t offset;
    uint32_t id;
  };
  union {
    uint32_t length;
    uint32_t ack_id;
  };
} PacketHeader;
static_assert(sizeof(PacketHeader) == 12, "packet header struct wrongly packed");

/* MTU mínimo do IPv4 (576) - cabeçalho IP máximo (60) - cabeçalho UDP (8) - cabeçalho do pacote */
#define MAX_PACKET_PAYLOAD_SIZE (508 - sizeof(PacketHeader))

/** Endereço de um peer (aponta para dados de um struct addrinfo). */
typedef struct {
  struct sockaddr *addr;
  socklen_t addrlen;
} Peer;

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

#define PEERS_CAP 8

/** Lista de endereços candidatos do outro peer, vindos do ERS. */
typedef struct {
  Peer peers[PEERS_CAP];
  struct addrinfo *infos[PEERS_CAP];  /* donos da memória apontada por peers[i].addr */
  int len;
} PeerList;

/** Libera a memória dos candidatos. */
void peer_list_free(PeerList *list) {
  for (int i = 0; i < list->len; i++) {
    freeaddrinfo(list->infos[i]);
  }
  list->len = 0;
}

/** Mensagens e endereço do ERS, preparados uma vez e reutilizados nas retransmissões. */
typedef struct {
  int id;
  struct addrinfo *server;
  char ip_string[PEERS_CAP][INET_ADDRSTRLEN];  /* nossos candidatos em texto */
  char register_req[32 + 24 * PEERS_CAP];
  size_t register_req_len;
  char expected_response[256];
  size_t expected_response_len;
  char query_req[256];
  size_t query_req_len;
} ErsSession;

/** Libera os recursos da sessão (pode ser chamada mais de uma vez). */
void ers_session_free(ErsSession *ers) {
  if (ers->server != NULL) {
    freeaddrinfo(ers->server);
    ers->server = NULL;
  }
}

/** Avisa que uma mensagem do ERS não coube no buffer. @return sempre -1. */
static int ers_request_too_long(void) {
  fprintf(stderr, "ERS request does not fit in its buffer\n");
  return -1;
}

/**
 * Monta as mensagens REGISTER, REGISTERED esperada e QUERY.
 * @return 0 em sucesso, -1 em falha (o motivo é impresso em stderr).
 */
static int ers_build_requests(ErsSession *ers, const Endpoint *my_endpoints, int my_endpoints_len,
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

/* ========================================================================== */
/* Remetente (send)                                                           */
/* ========================================================================== */

#define PACKS_PER_BLOCK 1024
#define BLOCK_SIZE (MAX_PACKET_PAYLOAD_SIZE * PACKS_PER_BLOCK)

/** Controle de cada pacote DATA de um bloco: quando foi enviado e se foi confirmado. */
typedef struct {
  uint32_t offset;  /* posição dentro do bloco */
  uint32_t length;
  double last_sent;
  bool confirmed;
} PacketTracker;

/** Estados da máquina de estados do remetente. */
typedef enum {
  S_ERS_SETUP = 0,
  S_ERS_REGISTER,
  S_ERS_GET_PEERS,
  S_WAITING_CONNECTION,
  S_OPEN_FILE,
  S_CREATE_NEW_BLOCK,
  S_HANDLE_ACKS,
  S_SEND_PACKET,
  S_SHOULD_CLOSE,
  S_CLOSING_CONNECTION,
  S_CLOSE_FILE,
  S_CLOSED_SHOULD_EXIT
} SM_Sender;

/* TODO: este intervalo deveria ser calculado dinamicamente para latências diferentes */
#define PACKET_RETRY_INTERVAL_SECONDS 0.5

/**
 * Executa o lado que envia o arquivo, do registro no ERS até o CLOSE_ACK.
 * Nunca bloqueia em rede: cada passada do laço trata um estado.
 * @return 0 se o arquivo foi enviado e confirmado, -1 em falha (o motivo é
 *         impresso em stderr).
 */
int sender(UDPRingBuffer *reader_ring, UDPRingBuffer *writer_ring, const Endpoint *my_endpoints,
           int my_endpoints_len, const char *filename, int ers_id) {
  SM_Sender state = S_ERS_SETUP;
  int result = -1;  /* só vira 0 se o laço terminar normalmente */
  bool failed = false;  /* qualquer falha fatal encerra o laço */

  ErsSession ers = {0};
  PeerList candidates = {0};
  Peer peer = {0};  /* peer escolhido (o que respondeu CONNECT_ACK) */

  double last_sent_register = 0;
  double last_sent_query = 0;
  double last_sent_connect[PEERS_CAP] = {0};
  double last_sent_close = 0;

  FILE *fp = NULL;
  uint32_t file_offset = 0;       /* offset do início do bloco atual */
  uint32_t file_next_offset = 0;  /* offset do início do próximo bloco */
  uint8_t file_buffer[BLOCK_SIZE];
  PacketTracker tracker[PACKS_PER_BLOCK] = {0};
  int tracker_len = 0;

  while (state != S_CLOSED_SHOULD_EXIT && !failed) {
    /* Uma falha fatal em reader/writer inviabiliza a transferência. */
    if (network_thread_failed(reader_ring, writer_ring)) {
      failed = true;
      break;
    }

    /* O tempo é lido uma vez por passada e usado por todos os temporizadores. */
    double now;
    if (seconds_since_unspecified_epoch(&now) != 0) {
      fprintf(stderr, "Could not read the clock: %s\n", strerror(errno));
      failed = true;
      break;
    }

    switch (state) {
      case S_ERS_SETUP: {
        if (ers_session_setup(&ers, my_endpoints, my_endpoints_len, ers_id) != 0) {
          failed = true;
          break;
        }
        state = S_ERS_REGISTER;
      } break;

      case S_ERS_REGISTER: {
        /* Reenvia o REGISTER até o ERS responder REGISTERED. Fila cheia aqui
         * é inofensivo: a próxima retransmissão acontece em 0,5 s. +1 inclui o '\0'. */
        if ((now - last_sent_register) > PACKET_RETRY_INTERVAL_SECONDS) {
          add_to_writer(writer_ring, ers.register_req, ers.register_req_len + 1, ers.server->ai_addr,
                        ers.server->ai_addrlen);
          last_sent_register = now;
        }

        UDPPacket udp_packet;
        int ret = take_from_reader(reader_ring, &udp_packet);
        if (ret == 0 && addr_cmp(udp_packet.addr, ers.server->ai_addr) == 0) {
          if (ers_reply_is_error(&udp_packet)) {
            ers_report_error(&udp_packet);
            failed = true;
            break;
          }

          if (udp_packet.len >= ers.expected_response_len &&
              memcmp(ers.expected_response, udp_packet.buf, ers.expected_response_len) == 0) {
            printf("Registered on ERS\n");
            state = S_ERS_GET_PEERS;
            break;
          }
        }
      } break;

      case S_ERS_GET_PEERS: {
        /* Consulta o ERS periodicamente até aparecerem candidatos do outro peer. */
        if ((now - last_sent_query) > PACKET_RETRY_INTERVAL_SECONDS) {
          add_to_writer(writer_ring, ers.query_req, ers.query_req_len, ers.server->ai_addr,
                        ers.server->ai_addrlen);
          last_sent_query = now;
        }

        UDPPacket udp_packet;
        int ret = take_from_reader(reader_ring, &udp_packet);
        if (ret == 0 && addr_cmp(udp_packet.addr, ers.server->ai_addr) == 0) {
          if (ers_reply_is_error(&udp_packet)) {
            ers_report_error(&udp_packet);
            failed = true;
            break;
          }

          ers_collect_peers(&ers, &udp_packet, my_endpoints, my_endpoints_len, &candidates);

          if (candidates.len >= 1) {
            printf("Found peer information\n");
            state = S_WAITING_CONNECTION;
            break;
          }
        }
      } break;

      case S_WAITING_CONNECTION: {
        /* Hole punching: envia CONNECT a todos os candidatos, repetidamente. */
        for (int i = 0; i < candidates.len; i++) {
          if ((now - last_sent_connect[i]) > PACKET_RETRY_INTERVAL_SECONDS) {
            send_connect(writer_ring, candidates.peers[i], 0, 0);
            last_sent_connect[i] = now;
          }
        }

        UDPPacket udp_packet;
        int ret = take_from_reader(reader_ring, &udp_packet);
        if (ret != 0) break;

        /* Ignora pacotes de endereços que não são candidatos conhecidos. */
        int i;
        for (i = 0; i < candidates.len; i++) {
          if (addr_cmp(udp_packet.addr, candidates.peers[i].addr) == 0) break;
        }

        if (i == candidates.len) break;

        PacketHeader ph = parse_packet(udp_packet.buf, udp_packet.len, NULL);
        if (ph.type == PACK_TYP_CONNECT_ACK) {
          /* O primeiro candidato que responde vence; os demais são descartados. */
          printf("Connected to peer\n");
          state = S_OPEN_FILE;
          peer = candidates.peers[i];
          break;
        }

        if (ph.type == PACK_TYP_CONNECT) {
          send_ack(writer_ring, candidates.peers[i], PACK_TYP_CONNECT_ACK, 0, 0);
          break;
        }
      } break;

      case S_OPEN_FILE: {
        fp = fopen(filename, "rb");
        if (fp == NULL) {
          fprintf(stderr, "Could not open '%s' for reading: %s\n", filename, strerror(errno));
          failed = true;
          break;
        }
        state = S_CREATE_NEW_BLOCK;
      } break;

      case S_CREATE_NEW_BLOCK: {
        /* Lê o próximo bloco do arquivo (até PACKS_PER_BLOCK pacotes). */
        file_offset = file_next_offset;
        size_t len = fread(file_buffer, 1, BLOCK_SIZE, fp);
        if (len == 0) {
          /* fread devolve 0 tanto no fim do arquivo quanto em erro de leitura. */
          if (ferror(fp)) {
            fprintf(stderr, "Error reading '%s': %s\n", filename, strerror(errno));
            failed = true;
            break;
          }

          printf("File sent! Closing connection\n");
          state = S_SHOULD_CLOSE;
          break;
        }

        /* Os offsets do protocolo têm 32 bits: arquivos acima de 4 GiB não cabem. */
        if (len > UINT32_MAX - file_next_offset) {
          fprintf(stderr, "File '%s' is too large (limit is 4 GiB)\n", filename);
          failed = true;
          break;
        }
        file_next_offset += (uint32_t)len;

        /* Divide o bloco em pacotes e zera o controle de envio/confirmação. */
        tracker_len = (int)((len + MAX_PACKET_PAYLOAD_SIZE - 1) / MAX_PACKET_PAYLOAD_SIZE);
        for (int i = 0; i < tracker_len; i++) {
          uint32_t offset = (uint32_t)((size_t)i * MAX_PACKET_PAYLOAD_SIZE);
          uint32_t remaining = (uint32_t)len - offset;
          uint32_t length =
              (remaining > MAX_PACKET_PAYLOAD_SIZE) ? (uint32_t)MAX_PACKET_PAYLOAD_SIZE : remaining;
          tracker[i] = (PacketTracker){
              .offset = offset,
              .length = length,
              .last_sent = 0,
              .confirmed = false,
          };
        }

        state = S_SEND_PACKET;
      } break;

      case S_SEND_PACKET: {
        /* Envia, em pequenos lotes, os pacotes nunca enviados ou cujo último
         * envio passou do intervalo de retransmissão. */
        bool has_unconfirmed_packets = false;
        int packets_sent_this_iteration = 0;
        for (int i = 0; i < tracker_len; i++) {
          if (tracker[i].confirmed) continue;
          has_unconfirmed_packets = true;

          if ((now - tracker[i].last_sent) > PACKET_RETRY_INTERVAL_SECONDS) {
            PacketTracker t = tracker[i];
            int ret = send_data(writer_ring, peer, file_offset + t.offset, t.length, &file_buffer[t.offset]);

            /* Fila de saída cheia: para e tenta de novo na próxima passada. */
            if (ret == -1) {
              break;
            }

            tracker[i].last_sent = now;

            packets_sent_this_iteration++;
            if (packets_sent_this_iteration > 8) break;
          }
        }

        /* Bloco todo confirmado: passa para o próximo. */
        if (!has_unconfirmed_packets) {
          state = S_CREATE_NEW_BLOCK;
          break;
        }

        state = S_HANDLE_ACKS;
      } break;

      case S_HANDLE_ACKS: {
        /* Lê todas as confirmações disponíveis e marca os pacotes pelo offset absoluto. */
        UDPPacket udp_packet;
        while (take_from_reader(reader_ring, &udp_packet) != -1) {
          if (addr_cmp(udp_packet.addr, peer.addr) != 0) continue;
          PacketHeader ph = parse_packet(udp_packet.buf, udp_packet.len, NULL);
          if (ph.type == PACK_TYP_DATA_ACK) {
            for (int i = 0; i < tracker_len; i++) {
              if (file_offset + tracker[i].offset == ph.offset) {
                tracker[i].confirmed = true;
              }
            }
          }
        }

        state = S_SEND_PACKET;
      } break;

      case S_SHOULD_CLOSE: {
        send_close(writer_ring, peer, 0, 0);
        last_sent_close = now;

        state = S_CLOSING_CONNECTION;
      } break;

      case S_CLOSING_CONNECTION: {
        /* Reenvia o CLOSE a cada intervalo até receber o CLOSE_ACK. */
        UDPPacket udp_packet;
        int ret = take_from_reader(reader_ring, &udp_packet);

        if (ret == 0 && addr_cmp(udp_packet.addr, peer.addr) == 0) {
          PacketHeader ph = parse_packet(udp_packet.buf, udp_packet.len, NULL);
          if (ph.type == PACK_TYP_CLOSE_ACK) {
            state = S_CLOSE_FILE;
            break;
          }
        }

        if ((now - last_sent_close) > PACKET_RETRY_INTERVAL_SECONDS) {
          send_close(writer_ring, peer, 0, 0);
          last_sent_close = now;
        }
      } break;

      case S_CLOSE_FILE: {
        /* O arquivo era só de leitura e o envio já foi confirmado: falha no
         * fclose não invalida a transferência, então só avisa. */
        int close_ret = fclose(fp);
        fp = NULL;
        if (close_ret != 0) {
          fprintf(stderr, "Warning: could not close '%s': %s\n", filename, strerror(errno));
        }
        state = S_CLOSED_SHOULD_EXIT;
      } break;

      case S_CLOSED_SHOULD_EXIT: {
        assert(false && "unreachable. state is exit condition from while");
      } break;
    }
  }

  if (!failed) result = 0;

  if (fp != NULL) fclose(fp);
  peer_list_free(&candidates);
  ers_session_free(&ers);
  return result;
}

/* ========================================================================== */
/* Destinatário (receive)                                                     */
/* ========================================================================== */

/** Estados da máquina de estados do destinatário. */
typedef enum {
  R_ERS_SETUP = 0,
  R_ERS_REGISTER,
  R_ERS_GET_PEERS,
  R_WAITING_CONNECTION,
  R_OPEN_FILE,
  R_READ_DATA,
  R_SEND_CLOSE_ACK,
  R_WAITING_TO_CLOSE,
  R_CLOSE_FILE,
  R_CLOSED_SHOULD_EXIT
} SM_Receiver;

/**
 * Executa o lado que recebe o arquivo, do registro no ERS até a espera final
 * depois do CLOSE.
 * @return 0 se o arquivo foi recebido e gravado, -1 em falha (o motivo é
 *         impresso em stderr).
 */
int receiver(UDPRingBuffer *reader_ring, UDPRingBuffer *writer_ring, const Endpoint *my_endpoints,
             int my_endpoints_len, const char *filename, int ers_id) {
  SM_Receiver state = R_ERS_SETUP;
  int result = -1;  /* só vira 0 se o laço terminar normalmente */
  bool failed = false;  /* qualquer falha fatal encerra o laço */

  ErsSession ers = {0};
  PeerList candidates = {0};
  Peer peer = {0};  /* peer fixado no primeiro DATA */

  double last_sent_register = 0;
  double last_sent_query = 0;
  double last_sent_connect[PEERS_CAP] = {0};
  bool got_connect_ack[PEERS_CAP] = {0};
  double last_sent_close_ack = 0;

  FILE *fp = NULL;

  while (state != R_CLOSED_SHOULD_EXIT && !failed) {
    /* Uma falha fatal em reader/writer inviabiliza a transferência. */
    if (network_thread_failed(reader_ring, writer_ring)) {
      failed = true;
      break;
    }

    /* O tempo é lido uma vez por passada e usado por todos os temporizadores. */
    double now;
    if (seconds_since_unspecified_epoch(&now) != 0) {
      fprintf(stderr, "Could not read the clock: %s\n", strerror(errno));
      failed = true;
      break;
    }

    switch (state) {
      case R_ERS_SETUP: {
        if (ers_session_setup(&ers, my_endpoints, my_endpoints_len, ers_id) != 0) {
          failed = true;
          break;
        }
        state = R_ERS_REGISTER;
      } break;

      case R_ERS_REGISTER: {
        /* Reenvia o REGISTER até o ERS responder REGISTERED. */
        if ((now - last_sent_register) > PACKET_RETRY_INTERVAL_SECONDS) {
          add_to_writer(writer_ring, ers.register_req, ers.register_req_len + 1, ers.server->ai_addr,
                        ers.server->ai_addrlen);
          last_sent_register = now;
        }

        UDPPacket udp_packet;
        int ret = take_from_reader(reader_ring, &udp_packet);
        if (ret == 0 && addr_cmp(udp_packet.addr, ers.server->ai_addr) == 0) {
          if (ers_reply_is_error(&udp_packet)) {
            ers_report_error(&udp_packet);
            failed = true;
            break;
          }

          if (udp_packet.len >= ers.expected_response_len &&
              memcmp(ers.expected_response, udp_packet.buf, ers.expected_response_len) == 0) {
            printf("Registered on ERS\n");
            state = R_ERS_GET_PEERS;
            break;
          }
        }
      } break;

      case R_ERS_GET_PEERS: {
        /* Consulta o ERS periodicamente até aparecerem candidatos do outro peer. */
        if ((now - last_sent_query) > PACKET_RETRY_INTERVAL_SECONDS) {
          add_to_writer(writer_ring, ers.query_req, ers.query_req_len, ers.server->ai_addr,
                        ers.server->ai_addrlen);
          last_sent_query = now;
        }

        UDPPacket udp_packet;
        int ret = take_from_reader(reader_ring, &udp_packet);
        if (ret == 0 && addr_cmp(udp_packet.addr, ers.server->ai_addr) == 0) {
          if (ers_reply_is_error(&udp_packet)) {
            ers_report_error(&udp_packet);
            failed = true;
            break;
          }

          ers_collect_peers(&ers, &udp_packet, my_endpoints, my_endpoints_len, &candidates);

          if (candidates.len >= 1) {
            printf("Found peer information\n");
            state = R_WAITING_CONNECTION;
            break;
          }
        }
      } break;

      case R_WAITING_CONNECTION: {
        /* Hole punching: envia CONNECT aos candidatos que ainda não responderam. */
        for (int i = 0; i < candidates.len; i++) {
          if (!got_connect_ack[i]) {
            if ((now - last_sent_connect[i]) > PACKET_RETRY_INTERVAL_SECONDS) {
              send_connect(writer_ring, candidates.peers[i], 0, 0);
              last_sent_connect[i] = now;
            }
          }
        }

        /* Só espia o pacote: se for DATA, ele precisa continuar na fila para o
         * estado R_READ_DATA gravá-lo. */
        UDPPacket udp_packet;
        int ret = peek_from_reader(reader_ring, &udp_packet);
        if (ret != 0) break;

        int i;
        for (i = 0; i < candidates.len; i++) {
          if (addr_cmp(udp_packet.addr, candidates.peers[i].addr) == 0) break;
        }

        /* Endereço desconhecido: descarta. */
        if (i == candidates.len) {
          take_from_reader(reader_ring, NULL);
          break;
        }

        /* O primeiro DATA prova que a conexão existe, mesmo que um CONNECT_ACK
         * tenha se perdido. Um CLOSE também prova (arquivo vazio: não há DATA). */
        PacketHeader ph = parse_packet(udp_packet.buf, udp_packet.len, NULL);
        if (ph.type == PACK_TYP_DATA || ph.type == PACK_TYP_CLOSE) {
          printf("Connected to peer\n");
          state = R_OPEN_FILE;
          peer = candidates.peers[i];
          break;
        }

        ret = take_from_reader(reader_ring, NULL);
        assert(ret == 0);

        if (ph.type == PACK_TYP_CONNECT) {
          send_ack(writer_ring, candidates.peers[i], PACK_TYP_CONNECT_ACK, 0, 0);
          break;
        }

        if (ph.type == PACK_TYP_CONNECT_ACK) {
          got_connect_ack[i] = true;
          break;
        }
      } break;

      case R_OPEN_FILE: {
        fp = fopen(filename, "wb");
        if (fp == NULL) {
          fprintf(stderr, "Could not open '%s' for writing: %s\n", filename, strerror(errno));
          failed = true;
          break;
        }
        state = R_READ_DATA;
      } break;

      case R_READ_DATA: {
        UDPPacket udp_packet;
        int ret = take_from_reader(reader_ring, &udp_packet);
        if (ret != 0 || addr_cmp(udp_packet.addr, peer.addr) != 0) break;

        const void *data = NULL;
        PacketHeader ph = parse_packet(udp_packet.buf, udp_packet.len, &data);

        if (ph.type == PACK_TYP_CLOSE) {
          printf("File received! Closing connection\n");
          state = R_SEND_CLOSE_ACK;
          break;
        }

        if (ph.type == PACK_TYP_DATA) {
          /* Grava na posição absoluta: ordem de chegada e duplicatas não importam. */
          if (fseeko(fp, (off_t)ph.offset, SEEK_SET) != 0) {
            fprintf(stderr, "Could not seek in '%s': %s\n", filename, strerror(errno));
            failed = true;
            break;
          }
          if (fwrite(data, 1, ph.length, fp) != ph.length) {
            fprintf(stderr, "Could not write to '%s': %s\n", filename, strerror(errno));
            failed = true;
            break;
          }
          /* Se a fila de saída estiver cheia o ACK não sai; o remetente retransmite o DATA. */
          send_data_ack(writer_ring, peer, ph.offset, ph.length);
          break;
        }
      } break;

      case R_SEND_CLOSE_ACK: {
        send_ack(writer_ring, peer, PACK_TYP_CLOSE_ACK, 0, 0);
        last_sent_close_ack = now;
        state = R_WAITING_TO_CLOSE;
      } break;

      case R_WAITING_TO_CLOSE: {
        /* Espera final (como o TIME_WAIT do TCP): responde a CLOSE repetidos, o
         * que cobre a perda do CLOSE_ACK. */
        UDPPacket udp_packet;
        int ret = take_from_reader(reader_ring, &udp_packet);

        if (ret != -1 && addr_cmp(udp_packet.addr, peer.addr) == 0) {
          PacketHeader ph = parse_packet(udp_packet.buf, udp_packet.len, NULL);

          if (ph.type == PACK_TYP_CLOSE) {
            state = R_SEND_CLOSE_ACK;
            break;
          }
        }

        if ((now - last_sent_close_ack) > 3 * PACKET_RETRY_INTERVAL_SECONDS) {
          state = R_CLOSE_FILE;
          break;
        }
      } break;

      case R_CLOSE_FILE: {
        /* fflush/fclose gravam o que ainda estava em buffer: se falharem
         * (ex.: disco cheio), o arquivo recebido está incompleto. */
        int flush_ret = fflush(fp);
        int flush_errno = errno;
        int close_ret = fclose(fp);
        int close_errno = errno;
        fp = NULL;

        if (flush_ret != 0 || close_ret != 0) {
          fprintf(stderr, "Could not finish writing '%s': %s\n", filename,
                  strerror(flush_ret != 0 ? flush_errno : close_errno));
          failed = true;
          break;
        }
        state = R_CLOSED_SHOULD_EXIT;
      } break;

      case R_CLOSED_SHOULD_EXIT: {
        assert(false && "unreachable. state is exit condition from while");
      } break;
    }
  }

  if (!failed) result = 0;

  if (fp != NULL) fclose(fp);
  peer_list_free(&candidates);
  ers_session_free(&ers);
  return result;
}

/* ========================================================================== */
/* main                                                                       */
/* ========================================================================== */

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
