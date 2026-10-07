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
#include "common.h"

#include "receiver.h"

/* ========================================================================== */
/* Destinatário (receive)                                                     */
/* ========================================================================== */

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
