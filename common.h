#pragma once

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

#include "endpoint.h"

/* ========================================================================== */
/* Filas circulares e threads de rede (reader / writer)                       */
/* ========================================================================== */

#define MAX_UDP_PACKET_SIZE 1500

/* TODO: este intervalo deveria ser calculado dinamicamente para latências diferentes */
#define PACKET_RETRY_INTERVAL_SECONDS 0.5

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
void *writer(void *arg);

/**
 * Coloca um pacote na fila de saída (o writer o enviará).
 * @return 0 em sucesso, -1 se a fila está cheia ou os argumentos são inválidos.
 *         Fila cheia não é falha fatal: os temporizadores do protocolo
 *         tentam enviar de novo mais tarde.
 */
int add_to_writer(UDPRingBuffer *ring, const void *buf, size_t len, const struct sockaddr *dest_addr,
                  socklen_t addrlen);

/**
 * Thread reader: fica em recvfrom() e coloca cada datagrama na fila de
 * entrada. O semáforo conta as vagas livres: com a fila cheia, a thread dorme.
 * Erros passageiros são ignorados; erros fatais vão para ring->failed.
 */
void *reader(void *arg);

/**
 * Retira o pacote mais antigo da fila de entrada (copiando-o para `packet`
 * quando não é NULL) e libera a vaga.
 * @return 0 se havia pacote, -1 se a fila está vazia.
 */
int take_from_reader(UDPRingBuffer *ring, UDPPacket *packet);

/**
 * Como take_from_reader, mas não remove o pacote da fila.
 * @return 0 se havia pacote, -1 se a fila está vazia.
 */
int peek_from_reader(UDPRingBuffer *ring, UDPPacket *packet);

/**
 * Compara dois endereços IPv4 (IP e porta).
 * @return 0 se forem iguais, 1 se forem diferentes ou inválidos.
 */
int addr_cmp(const struct sockaddr *a, const struct sockaddr *b);

/**
 * Verifica se alguma thread de rede registrou uma falha fatal.
 * @return true (e imprime o motivo em stderr) se reader ou writer falhou.
 */
bool network_thread_failed(UDPRingBuffer *reader_ring, UDPRingBuffer *writer_ring);

/* ========================================================================== */
/* Formato dos pacotes do protocolo                                           */
/* ========================================================================== */

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
int send_ack(UDPRingBuffer *packet_ring, Peer peer, PacketType type, uint32_t id, uint32_t ack_id);

/** Envia um CONNECT. @return 0 em sucesso, -1 se a fila de saída está cheia. */
int send_connect(UDPRingBuffer *packet_ring, Peer peer, uint32_t id, uint32_t ack_id);

/** Envia um CLOSE. @return 0 em sucesso, -1 se a fila de saída está cheia. */
int send_close(UDPRingBuffer *packet_ring, Peer peer, uint32_t id, uint32_t ack_id);

/**
 * Envia um DATA com `length` bytes do arquivo que começam em `offset`.
 * @return 0 em sucesso, -1 se a fila está cheia ou `length` é grande demais.
 */
int send_data(UDPRingBuffer *packet_ring, Peer peer, uint32_t offset, uint32_t length, const void *data);

/** Envia um DATA_ACK para o DATA com o mesmo offset. @return 0 ou -1 (fila cheia). */
int send_data_ack(UDPRingBuffer *packet_ring, Peer peer, uint32_t offset, uint32_t length);

/**
 * Interpreta um datagrama recebido.
 * @param data se não for NULL, recebe um ponteiro para o payload (logo após o cabeçalho).
 * @return o cabeçalho; type == PACK_INVALID se o pacote for curto demais ou
 *         se um DATA declarar mais bytes do que realmente chegaram.
 */
PacketHeader parse_packet(const void *packet, size_t packet_len, const void **data);

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
void peer_list_free(PeerList *list);

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
void ers_session_free(ErsSession *ers);

/** Avisa que uma mensagem do ERS não coube no buffer. @return sempre -1. */
int ers_request_too_long(void);

/**
 * Monta as mensagens REGISTER, REGISTERED esperada e QUERY.
 * @return 0 em sucesso, -1 em falha (o motivo é impresso em stderr).
 */
int ers_build_requests(ErsSession *ers, const Endpoint *my_endpoints, int my_endpoints_len,
                              int ers_id);

/**
 * Resolve o endereço do ERS (ERS_ADDR/ERS_PORT, padrão ers.grfreire.com:54321)
 * e monta as mensagens REGISTER e QUERY com os nossos candidatos.
 * @return 0 em sucesso, -1 em falha (o motivo é impresso em stderr).
 */
int ers_session_setup(ErsSession *ers, const Endpoint *my_endpoints, int my_endpoints_len, int ers_id);

/** Diz se o pacote é uma resposta de erro do ERS ("ERROR\n<motivo>\n"). */
bool ers_reply_is_error(const UDPPacket *packet);

/** Imprime em stderr o texto de uma resposta de erro do ERS. */
void ers_report_error(const UDPPacket *packet);

/**
 * Interpreta uma resposta "ENTRIES <id>\n<ip:porta>\n..." do ERS e acrescenta
 * à lista os candidatos que não são nossos. Linhas inválidas são ignoradas.
 * Modifica o conteúdo de `packet->buf` (o texto é cortado com strsep).
 * @return quantos candidatos novos foram acrescentados (0 se a resposta não
 *         era um ENTRIES válido para o nosso ID).
 */
int ers_collect_peers(const ErsSession *ers, UDPPacket *packet, const Endpoint *my_endpoints,
                      int my_endpoints_len, PeerList *list);
