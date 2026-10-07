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

#include "common.h"
#include "endpoint.h"

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

/**
 * Executa o lado que envia o arquivo, do registro no ERS até o CLOSE_ACK.
 * Nunca bloqueia em rede: cada passada do laço trata um estado.
 * @return 0 se o arquivo foi enviado e confirmado, -1 em falha (o motivo é
 *         impresso em stderr).
 */
int sender(UDPRingBuffer *reader_ring, UDPRingBuffer *writer_ring, const Endpoint *my_endpoints,
           int my_endpoints_len, const char *filename, int ers_id);
