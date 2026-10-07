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

/** Endereço IPv4 + porta, ambos em ordem de bytes do host. */
typedef struct {
  uint32_t addr;
  uint16_t port;
} Endpoint;

/** Imprime um Endpoint (função de depuração). */
void print_endpoint(Endpoint endpoint);

/** Imprime um struct sockaddr com um rótulo (função de depuração). */
void print_addr(const char *label, const struct sockaddr *addr);

/**
 * Descobre o IP e a porta públicos do socket enviando um Binding Request ao
 * servidor STUN pelo próprio socket (o NAT mapeia a porta local do socket).
 * O servidor vem de STUN_ADDR/STUN_PORT (padrão: stun.l.google.com:19302).
 *
 * @param sock         socket UDP que será usado na transferência.
 * @param out_endpoint recebe o endereço público em caso de sucesso.
 * @return 0 em sucesso, -1 em falha (o motivo é impresso em stderr).
 */
int get_socket_public_endpoint(int sock, Endpoint *out_endpoint);

/**
 * Descobre a porta local do socket (fazendo bind em porta livre se ainda não
 * houver) para montar o candidato de loopback. O campo addr não é preenchido
 * com 127.0.0.1 aqui: quem chama define o IP.
 * @return 0 em sucesso, -1 em falha.
 */
int get_socket_loopback_endpoint(int sock, Endpoint *out_endpoint);

/**
 * Descobre o IP da interface de rede local usada para sair para a internet.
 * Usa o truque de "conectar" um socket UDP a um endereço de documentação
 * (192.0.2.1): nenhum pacote é enviado, mas o kernel escolhe a interface e
 * getsockname revela o IP dela.
 * @param out_addr recebe o IP em ordem de bytes do host.
 * @return 0 em sucesso, -1 em falha (ex.: sem rota de rede).
 */
int get_lan_ip(uint32_t *out_addr);
