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

/* ========================================================================== */
/* Utilitários                                                                */
/* ========================================================================== */

#define NANOS_PER_SEC (1000 * 1000 * 1000)

/**
 * Lê o relógio monotônico (não é afetado por ajustes da hora do sistema).
 * @param out_seconds recebe o tempo em segundos, com origem não especificada.
 * @return 0 em sucesso, -1 em falha (errno é preenchido por clock_gettime).
 */
int seconds_since_unspecified_epoch(double *out_seconds);

/**
 * Diz se um erro de rede é passageiro. Em UDP isso não precisa derrubar o
 * programa: o pacote perdido é recuperado pela retransmissão do protocolo.
 */
bool is_transient_net_error(int err);

/**
 * Converte um texto em inteiro validando o texto inteiro e o intervalo.
 * Espaços no começo e no fim são aceitos.
 * @return 0 em sucesso, -1 se o texto não for um número em [min, max].
 */
int parse_long(const char *str, long min, long max, long *out);

/** Diz se o retorno de snprintf indica que o texto coube inteiro no buffer. */
bool snprintf_ok(int written, size_t buf_size);
