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

#include "endpoint.h"

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
