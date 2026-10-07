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
             int my_endpoints_len, const char *filename, int ers_id);
