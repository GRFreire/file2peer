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
/* STUN (RFC 5389): descobre o endereço público do socket                     */
/* ========================================================================== */

#define STUN_MAGIC_COOKIE 0x2112A442
#define STUN_BINDING_REQUEST 0x0001
#define STUN_BINDING_SUCCESS_RESPONSE 0x0101
#define STUN_XOR_MAPPED_ADDRESS 0x0020
#define STUN_IPV4_FAMILY 0x01
#define STUN_BUFFER_SIZE 1500

#define STUN_RETRY_INTERVAL 0.5  /* segundos entre Binding Requests */
#define STUN_MAX_TRY_TIME 2      /* segundos até desistir do STUN */

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

/** Dicas para getaddrinfo: apenas IPv4, UDP e porta numérica. */
static struct addrinfo addr_hints = {.ai_family = AF_INET, .ai_socktype = SOCK_DGRAM, .ai_flags = AI_NUMERICSERV};

/**
 * Troca de mensagens com o servidor STUN já resolvido: reenvia o Binding Request
 * até chegar a resposta ou estourar STUN_MAX_TRY_TIME.
 * @return 0 em sucesso, -1 em falha (o motivo é impresso em stderr).
 */
int stun_exchange(int sock, const struct addrinfo *stun_server, const char *stun_addr,
                         const char *stun_port, Endpoint *out_endpoint);
