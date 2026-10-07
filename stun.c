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

#include "stun.h"

/* ========================================================================== */
/* STUN (RFC 5389): descobre o endereço público do socket                     */
/* ========================================================================== */

/**
 * Troca de mensagens com o servidor STUN já resolvido: reenvia o Binding Request
 * até chegar a resposta ou estourar STUN_MAX_TRY_TIME.
 * @return 0 em sucesso, -1 em falha (o motivo é impresso em stderr).
 */
int stun_exchange(int sock, const struct addrinfo *stun_server, const char *stun_addr,
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
