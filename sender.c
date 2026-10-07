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

#include "sender.h"

/* ========================================================================== */
/* Remetente (send)                                                           */
/* ========================================================================== */

/**
 * Executa o lado que envia o arquivo, do registro no ERS até o CLOSE_ACK.
 * Nunca bloqueia em rede: cada passada do laço trata um estado.
 * @return 0 se o arquivo foi enviado e confirmado, -1 em falha (o motivo é
 *         impresso em stderr).
 */
int sender(UDPRingBuffer *reader_ring, UDPRingBuffer *writer_ring, const Endpoint *my_endpoints,
           int my_endpoints_len, const char *filename, int ers_id) {
  SM_Sender state = S_ERS_SETUP;
  int result = -1;  /* só vira 0 se o laço terminar normalmente */
  bool failed = false;  /* qualquer falha fatal encerra o laço */

  ErsSession ers = {0};
  PeerList candidates = {0};
  Peer peer = {0};  /* peer escolhido (o que respondeu CONNECT_ACK) */

  double last_sent_register = 0;
  double last_sent_query = 0;
  double last_sent_connect[PEERS_CAP] = {0};
  double last_sent_close = 0;

  FILE *fp = NULL;
  uint32_t file_offset = 0;       /* offset do início do bloco atual */
  uint32_t file_next_offset = 0;  /* offset do início do próximo bloco */
  uint8_t file_buffer[BLOCK_SIZE];
  PacketTracker tracker[PACKS_PER_BLOCK] = {0};
  int tracker_len = 0;

  while (state != S_CLOSED_SHOULD_EXIT && !failed) {
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
      case S_ERS_SETUP: {
        if (ers_session_setup(&ers, my_endpoints, my_endpoints_len, ers_id) != 0) {
          failed = true;
          break;
        }
        state = S_ERS_REGISTER;
      } break;

      case S_ERS_REGISTER: {
        /* Reenvia o REGISTER até o ERS responder REGISTERED. Fila cheia aqui
         * é inofensivo: a próxima retransmissão acontece em 0,5 s. +1 inclui o '\0'. */
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
            state = S_ERS_GET_PEERS;
            break;
          }
        }
      } break;

      case S_ERS_GET_PEERS: {
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
            state = S_WAITING_CONNECTION;
            break;
          }
        }
      } break;

      case S_WAITING_CONNECTION: {
        /* Hole punching: envia CONNECT a todos os candidatos, repetidamente. */
        for (int i = 0; i < candidates.len; i++) {
          if ((now - last_sent_connect[i]) > PACKET_RETRY_INTERVAL_SECONDS) {
            send_connect(writer_ring, candidates.peers[i], 0, 0);
            last_sent_connect[i] = now;
          }
        }

        UDPPacket udp_packet;
        int ret = take_from_reader(reader_ring, &udp_packet);
        if (ret != 0) break;

        /* Ignora pacotes de endereços que não são candidatos conhecidos. */
        int i;
        for (i = 0; i < candidates.len; i++) {
          if (addr_cmp(udp_packet.addr, candidates.peers[i].addr) == 0) break;
        }

        if (i == candidates.len) break;

        PacketHeader ph = parse_packet(udp_packet.buf, udp_packet.len, NULL);
        if (ph.type == PACK_TYP_CONNECT_ACK) {
          /* O primeiro candidato que responde vence; os demais são descartados. */
          printf("Connected to peer\n");
          state = S_OPEN_FILE;
          peer = candidates.peers[i];
          break;
        }

        if (ph.type == PACK_TYP_CONNECT) {
          send_ack(writer_ring, candidates.peers[i], PACK_TYP_CONNECT_ACK, 0, 0);
          break;
        }
      } break;

      case S_OPEN_FILE: {
        fp = fopen(filename, "rb");
        if (fp == NULL) {
          fprintf(stderr, "Could not open '%s' for reading: %s\n", filename, strerror(errno));
          failed = true;
          break;
        }
        state = S_CREATE_NEW_BLOCK;
      } break;

      case S_CREATE_NEW_BLOCK: {
        /* Lê o próximo bloco do arquivo (até PACKS_PER_BLOCK pacotes). */
        file_offset = file_next_offset;
        size_t len = fread(file_buffer, 1, BLOCK_SIZE, fp);
        if (len == 0) {
          /* fread devolve 0 tanto no fim do arquivo quanto em erro de leitura. */
          if (ferror(fp)) {
            fprintf(stderr, "Error reading '%s': %s\n", filename, strerror(errno));
            failed = true;
            break;
          }

          printf("File sent! Closing connection\n");
          state = S_SHOULD_CLOSE;
          break;
        }

        /* Os offsets do protocolo têm 32 bits: arquivos acima de 4 GiB não cabem. */
        if (len > UINT32_MAX - file_next_offset) {
          fprintf(stderr, "File '%s' is too large (limit is 4 GiB)\n", filename);
          failed = true;
          break;
        }
        file_next_offset += (uint32_t)len;

        /* Divide o bloco em pacotes e zera o controle de envio/confirmação. */
        tracker_len = (int)((len + MAX_PACKET_PAYLOAD_SIZE - 1) / MAX_PACKET_PAYLOAD_SIZE);
        for (int i = 0; i < tracker_len; i++) {
          uint32_t offset = (uint32_t)((size_t)i * MAX_PACKET_PAYLOAD_SIZE);
          uint32_t remaining = (uint32_t)len - offset;
          uint32_t length =
              (remaining > MAX_PACKET_PAYLOAD_SIZE) ? (uint32_t)MAX_PACKET_PAYLOAD_SIZE : remaining;
          tracker[i] = (PacketTracker){
              .offset = offset,
              .length = length,
              .last_sent = 0,
              .confirmed = false,
          };
        }

        state = S_SEND_PACKET;
      } break;

      case S_SEND_PACKET: {
        /* Envia, em pequenos lotes, os pacotes nunca enviados ou cujo último
         * envio passou do intervalo de retransmissão. */
        bool has_unconfirmed_packets = false;
        int packets_sent_this_iteration = 0;
        for (int i = 0; i < tracker_len; i++) {
          if (tracker[i].confirmed) continue;
          has_unconfirmed_packets = true;

          if ((now - tracker[i].last_sent) > PACKET_RETRY_INTERVAL_SECONDS) {
            PacketTracker t = tracker[i];
            int ret = send_data(writer_ring, peer, file_offset + t.offset, t.length, &file_buffer[t.offset]);

            /* Fila de saída cheia: para e tenta de novo na próxima passada. */
            if (ret == -1) {
              break;
            }

            tracker[i].last_sent = now;

            packets_sent_this_iteration++;
            if (packets_sent_this_iteration > 8) break;
          }
        }

        /* Bloco todo confirmado: passa para o próximo. */
        if (!has_unconfirmed_packets) {
          state = S_CREATE_NEW_BLOCK;
          break;
        }

        state = S_HANDLE_ACKS;
      } break;

      case S_HANDLE_ACKS: {
        /* Lê todas as confirmações disponíveis e marca os pacotes pelo offset absoluto. */
        UDPPacket udp_packet;
        while (take_from_reader(reader_ring, &udp_packet) != -1) {
          if (addr_cmp(udp_packet.addr, peer.addr) != 0) continue;
          PacketHeader ph = parse_packet(udp_packet.buf, udp_packet.len, NULL);
          if (ph.type == PACK_TYP_DATA_ACK) {
            for (int i = 0; i < tracker_len; i++) {
              if (file_offset + tracker[i].offset == ph.offset) {
                tracker[i].confirmed = true;
              }
            }
          }
        }

        state = S_SEND_PACKET;
      } break;

      case S_SHOULD_CLOSE: {
        send_close(writer_ring, peer, 0, 0);
        last_sent_close = now;

        state = S_CLOSING_CONNECTION;
      } break;

      case S_CLOSING_CONNECTION: {
        /* Reenvia o CLOSE a cada intervalo até receber o CLOSE_ACK. */
        UDPPacket udp_packet;
        int ret = take_from_reader(reader_ring, &udp_packet);

        if (ret == 0 && addr_cmp(udp_packet.addr, peer.addr) == 0) {
          PacketHeader ph = parse_packet(udp_packet.buf, udp_packet.len, NULL);
          if (ph.type == PACK_TYP_CLOSE_ACK) {
            state = S_CLOSE_FILE;
            break;
          }
        }

        if ((now - last_sent_close) > PACKET_RETRY_INTERVAL_SECONDS) {
          send_close(writer_ring, peer, 0, 0);
          last_sent_close = now;
        }
      } break;

      case S_CLOSE_FILE: {
        /* O arquivo era só de leitura e o envio já foi confirmado: falha no
         * fclose não invalida a transferência, então só avisa. */
        int close_ret = fclose(fp);
        fp = NULL;
        if (close_ret != 0) {
          fprintf(stderr, "Warning: could not close '%s': %s\n", filename, strerror(errno));
        }
        state = S_CLOSED_SHOULD_EXIT;
      } break;

      case S_CLOSED_SHOULD_EXIT: {
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
