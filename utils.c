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

/* ========================================================================== */
/* Utilitários                                                                */
/* ========================================================================== */

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
