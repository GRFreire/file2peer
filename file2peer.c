#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define STUN_MAGIC_COOKIE 0x2112A442
#define STUN_BINDING_REQUEST 0x0001
#define STUN_BINDING_SUCCESS_RESPONSE 0x0101
#define STUN_XOR_MAPPED_ADDRESS 0x0020
#define STUN_IPV4_FAMILY 0x01
#define STUN_BUFFER_SIZE 1500

typedef struct {
  uint16_t type;
  uint16_t length;
  uint32_t cookie;
  uint8_t transaction_id[12];
} stun_header;
static_assert(sizeof(stun_header) == 20, "stun header struct wrongly packed");

typedef struct {
  uint16_t type;
  uint16_t length;
} stun_tlv;
static_assert(sizeof(stun_tlv) == 4, "stun tlv struct wrongly packed");

typedef struct {
  uint8_t zeros;
  uint8_t family;
  uint16_t xor_port;
  uint32_t xor_addr;
} stun_xor_mapped_addr;
static_assert(sizeof(stun_xor_mapped_addr) == 8, "stun tlv struct wrongly packed");

typedef struct {
  uint32_t addr;
  uint16_t port;
} Endpoint;

void print_endpoint(Endpoint endpoint) {
  struct in_addr ip;
  ip.s_addr = htonl(endpoint.addr);

  char ip_string[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &ip, ip_string, sizeof(ip_string));

  printf("Endpoint: %s:%u\n", ip_string, endpoint.port);
}

struct addrinfo addr_hints = {
  .ai_family   = AF_INET,
  .ai_socktype = SOCK_DGRAM,
  .ai_flags    = AI_NUMERICSERV
};

int get_socket_public_endpoint(int sock, Endpoint *out_endpoint) {
  struct addrinfo *stun_server;
  int ret = getaddrinfo("stun.l.google.com", "19302", &addr_hints, &stun_server);
  if (ret != 0) {
    fprintf(stderr, "Could not get addrinfo for STUN server\n");
    return -1;
  }

  stun_header req_header = {
    .type           = htons(STUN_BINDING_REQUEST),
    .length         = htons(0),
    .cookie         = htonl(STUN_MAGIC_COOKIE),
    .transaction_id = {0},
  };
  getrandom(req_header.transaction_id, 12, 0);

  ret = sendto(sock, &req_header, sizeof(req_header), 0, stun_server->ai_addr, stun_server->ai_addrlen);
  if (ret == -1) {
    fprintf(stderr, "Could not send data to STUN server: %s\n", strerror(errno));
    freeaddrinfo(stun_server);
    return -1;
  }

  freeaddrinfo(stun_server);

  uint8_t response[STUN_BUFFER_SIZE];
  ssize_t bytes_recv = recvfrom(sock, &response, sizeof(response), 0, NULL, NULL);
  if (bytes_recv == -1) {
    fprintf(stderr, "Could not receive data: %s\n", strerror(errno));
    return -1;
  } else if ((size_t)bytes_recv < sizeof(stun_header)) {
    fprintf(stderr, "Not enought data received to parse STUN header. Needed %ld, got %ld\n",
            sizeof(stun_header), bytes_recv);
    return -1;
  }

  size_t offset = 0;
  stun_header res_header;
  memcpy(&res_header, &response[offset], sizeof(res_header));
  offset += sizeof(stun_header);

  res_header.type   = ntohs(res_header.type);
  res_header.length = ntohs(res_header.length);
  res_header.cookie = ntohl(res_header.cookie);

  if (res_header.cookie != STUN_MAGIC_COOKIE) {
    fprintf(stderr, "Wrong magic cookie\n");
    return -1;
  }

  if (res_header.type != STUN_BINDING_SUCCESS_RESPONSE) {
    fprintf(stderr, "Not a successful Stun Binding Response\n");
    return -1;
  }

  if (memcmp(req_header.transaction_id, res_header.transaction_id, sizeof(req_header.transaction_id)) != 0) {
    fprintf(stderr, "Wrong transaction id\n");
    return -1;
  }

  if ((size_t)bytes_recv < res_header.length + sizeof(stun_header)) {
    fprintf(stderr, "Could not read enough data to parse entire response\n");
    return -1;
  }

  Endpoint endpoint = {0};
  bool found = false;
  while (offset + sizeof(stun_tlv) <= (size_t)res_header.length + sizeof(stun_header)) {
    stun_tlv tlv;
    memcpy(&tlv, &response[offset], sizeof(tlv));
    offset += sizeof(stun_tlv);

    tlv.type   = ntohs(tlv.type);
    tlv.length = ntohs(tlv.length);

    // always 4-bytes aligned
    size_t next_attr_offset = (tlv.length + 3) & ~3;

    if (offset + tlv.length > (size_t)res_header.length + sizeof(stun_header)) {
      // not enought data read to parse tlv
      break;
    }

    if (tlv.type != STUN_XOR_MAPPED_ADDRESS) {
      // not xor-mapped address, skipping
      offset += next_attr_offset;
      continue;
    }

    if (tlv.length < 8) {
      // invalid, skipping
      offset += next_attr_offset;
      continue;
    }

    stun_xor_mapped_addr stun_addr;
    memcpy(&stun_addr, &response[offset], sizeof(stun_addr));
    offset += next_attr_offset;

    if (stun_addr.family != STUN_IPV4_FAMILY) {
      // not ipv4, skipping
      continue;
    }

    endpoint.port = ntohs(stun_addr.xor_port) ^ (STUN_MAGIC_COOKIE >> 16);
    endpoint.addr = ntohl(stun_addr.xor_addr) ^ (STUN_MAGIC_COOKIE);
    found = true;
    break;
  }

  if (!found) {
    fprintf(stderr, "Could not find any IPv4 response\n");
    return -1;
  }

  *out_endpoint = endpoint;
  return 0;
}

int get_socket_local_endpoint(int sock, Endpoint *out_endpoint) {
  struct sockaddr_in addr;
  socklen_t addr_len = sizeof(addr);
  
  if (getsockname(sock, (struct sockaddr *)&addr, &addr_len) == -1) {
    fprintf(stderr, "Could not get local socket endpoint\n");
    return -1;
  }

  if (addr.sin_port == 0) {
    int ret = bind(sock, (struct sockaddr *)&addr, addr_len);
    if (ret == -1) {
      fprintf(stderr, "Could not bind to any port\n");
      return -1;
    }

    if (getsockname(sock, (struct sockaddr *)&addr, &addr_len) == -1) {
      fprintf(stderr, "Could not get local socket endpoint\n");
      return -1;
    }
  }
  
  out_endpoint->port = ntohs(addr.sin_port);
  out_endpoint->addr = ntohl(addr.sin_addr.s_addr);
  return 0;
}

// ----------------------------------------------
//
#define MAX_UDP_PACKET_SIZE 1500
typedef struct {
  size_t len;
  struct sockaddr *dest_addr;
  socklen_t addrlen;
  uint8_t buf[MAX_UDP_PACKET_SIZE];
} UDPPacket;

#define RING_BUFFER_CAP 1024
typedef struct {
  _Atomic int head;
  _Atomic int tail;
  UDPPacket *data;
  sem_t sem;
} UDPRingBuffer;

typedef struct {
  int sock;
  _Atomic int should_exit;
  UDPRingBuffer *ring;
} ThreadArgs;

void *writer(void *arg) {
  ThreadArgs *args = (ThreadArgs *)arg;
  UDPRingBuffer *ring = args->ring;

  while (true) {
    sem_wait(&ring->sem);

    int should_exit = atomic_load(&args->should_exit);
    int tail = atomic_load(&ring->tail);
    int head = atomic_load(&ring->head);
      
    if (should_exit && head == tail) {
      pthread_exit(NULL);
    }

    UDPPacket p = ring->data[tail];
    tail++;
    tail %= RING_BUFFER_CAP;

    sendto(args->sock, &p.buf, p.len, 0, p.dest_addr, p.addrlen);

    atomic_store(&ring->tail, tail);
  }

  return NULL;
}

int add_to_writer(UDPRingBuffer *ring, void *buf, size_t len, struct sockaddr *dest_addr, socklen_t addrlen) {
  assert(len <= MAX_UDP_PACKET_SIZE);

  int head = atomic_load(&ring->head);
  int tail = atomic_load(&ring->tail);
  int new_head = (head + 1) % RING_BUFFER_CAP;
  if (new_head == tail) {
    return -1;
  }

  UDPPacket *p = &ring->data[head];
  p->len = len;
  p->dest_addr = dest_addr;
  p->addrlen = addrlen;
  memcpy(p->buf, buf, len);

  atomic_store(&ring->head, new_head);
  sem_post(&ring->sem);

  return 0;
}

void *reader(void *arg) {
  ThreadArgs *args = (ThreadArgs *)arg;
  UDPRingBuffer *ring = args->ring;

  while (true) {
    sem_wait(&ring->sem);
    int should_exit = atomic_load(&args->should_exit);
    if (should_exit) {
      pthread_exit(NULL);
    }

    int head = atomic_load(&ring->head);
    int tail = atomic_load(&ring->tail);
    int new_head = (head + 1) % RING_BUFFER_CAP;
    if (new_head == tail) {
      // ring full
      assert(false && "semaphore should have handled full ring");
    }

    UDPPacket *p = &ring->data[head];
    ssize_t bytes_recv = recvfrom(args->sock, &p->buf, MAX_UDP_PACKET_SIZE, 0, NULL, NULL); 
    if (bytes_recv == (ssize_t)-1) {
      sem_post(&ring->sem);
      continue;
    }

    p->len = bytes_recv;
    p->dest_addr = NULL;
    p->addrlen = 0;

    atomic_store(&ring->head, new_head);
  }

  return NULL;
}

int take_from_reader(UDPRingBuffer *ring, UDPPacket *packet) {
  int tail = atomic_load(&ring->tail);
  int head = atomic_load(&ring->head);


  if (head == tail) {
    return -1;
  }

  if (packet != NULL) {
    *packet = ring->data[tail];
  }

  atomic_store(&ring->tail, (tail + 1) % RING_BUFFER_CAP);
  sem_post(&ring->sem);
  return 0;
}

int peek_from_reader(UDPRingBuffer *ring, UDPPacket *packet) {
  int tail = atomic_load(&ring->tail);
  int head = atomic_load(&ring->head);


  if (head == tail) {
    return -1;
  }

  *packet = ring->data[tail];
  return 0;
}

#define LINE_BUF_SIZE 100

typedef enum {
    _RESERVED = 0,
    PACK_INVALID,
    PACK_TYP_CONNECT,
    PACK_TYP_CONNECT_ACK,
    PACK_TYP_CLOSE,
    PACK_TYP_CLOSE_ACK,
    PACK_TYP_DATA,
    PACK_TYP_DATA_ACK,
} PacketType;

typedef struct {
    uint8_t type;
    uint8_t _reserved;
    uint16_t checksum;
    union {
        uint32_t offset;
        uint32_t id;
    };
    union {
        uint32_t length;
        uint32_t ack_id;
    };
} PacketHeader;
static_assert(sizeof(PacketHeader) == 12, "packet header struct wrongly packed");

// Minimum MTU - max size IP Header - UDP Header - Packet Header
#define MAX_PACKET_PAYLOAD_SIZE (508 - sizeof(PacketHeader))

typedef struct {
    int fd;
    struct sockaddr *addr;
    socklen_t addr_len;
} Peer;

int send_ack(UDPRingBuffer *packet_ring, Peer peer, PacketType type, uint32_t id, uint32_t ack_id) {
    PacketHeader p = {
        .type = type,
        ._reserved = 0,
        .checksum = 0,
        .id = id,
        .ack_id = ack_id,
    };

    return add_to_writer(packet_ring, &p, sizeof(p), peer.addr, peer.addr_len);
}
int send_connect(UDPRingBuffer *packet_ring, Peer peer, uint32_t id, uint32_t ack_id) {
    PacketHeader p = {
        .type = PACK_TYP_CONNECT,
        ._reserved = 0,
        .checksum = 0,
        .id = id,
        .ack_id = ack_id,
    };

    return add_to_writer(packet_ring, &p, sizeof(p), peer.addr, peer.addr_len);
}
int send_close(UDPRingBuffer *packet_ring, Peer peer, uint32_t id, uint32_t ack_id) {
    PacketHeader p = {
        .type = PACK_TYP_CLOSE,
        ._reserved = 0,
        .checksum = 0,
        .id = id,
        .ack_id = ack_id,
    };

    return add_to_writer(packet_ring, &p, sizeof(p), peer.addr, peer.addr_len);
}
int send_data(UDPRingBuffer *packet_ring, Peer peer, uint32_t offset, uint32_t length, void *data) {
    assert(length <= MAX_PACKET_PAYLOAD_SIZE);
    uint8_t buffer[MAX_PACKET_PAYLOAD_SIZE + sizeof(PacketHeader)] = {0};
    PacketHeader p = {
        .type = PACK_TYP_DATA,
        ._reserved = 0,
        .checksum = 0,
        .offset = offset,
        .length = length,
    };

    memcpy(&buffer[0], &p, sizeof(p));
    memcpy(&buffer[sizeof(p)], data, length);

    return add_to_writer(packet_ring, buffer, sizeof(PacketHeader) + length, peer.addr, peer.addr_len);
}
int send_data_ack(UDPRingBuffer *packet_ring, Peer peer, uint32_t offset, uint32_t length) {
    PacketHeader p = {
        .type = PACK_TYP_DATA_ACK,
        ._reserved = 0,
        .checksum = 0,
        .offset = offset,
        .length = length,
    };

    return add_to_writer(packet_ring, &p, sizeof(p), peer.addr, peer.addr_len);
}

PacketHeader parse_packet(void *packet, size_t packet_len, void **data) {
    PacketHeader ph = {0};
      
    if (packet_len < (ssize_t)sizeof(PacketHeader)) {
      printf("Received malformed packet\n");
      ph.type = PACK_INVALID;
      return ph;
    }

    memcpy(&ph, packet, sizeof(PacketHeader));

    if (ph.type == PACK_TYP_DATA) {
        if (ph.length + sizeof(PacketHeader) > packet_len) {
            printf("data packet incomplete (not enought data)\n");
            ph.type = PACK_INVALID;
            return ph;
        }
    }

    if (data != NULL) {
        *data = packet + sizeof(PacketHeader);
    }
    return ph;
}

#define PACKS_PER_BLOCK 1024
#define BLOCK_SIZE (MAX_PACKET_PAYLOAD_SIZE * PACKS_PER_BLOCK)

typedef struct {
    uint32_t offset;
    uint32_t length;
    double last_sent;
    bool confirmed;
} PacketTracker;

typedef enum {
  S_UNCONNECTED = 0,
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

#define NANOS_PER_SEC (1000 * 1000 * 1000)
double seconds_since_unspecified_epoch(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);

  return (double)(NANOS_PER_SEC * ts.tv_sec + ts.tv_nsec) / NANOS_PER_SEC;
}

// TODO: this should be dynamically calculated to account for diferent latencies
#define PACKET_RETRY_INTERVAL_SECONDS 0.5

void sender(UDPRingBuffer *reader_ring, UDPRingBuffer *writer_ring, Peer peer) {
  SM_Sender state = S_UNCONNECTED;

  double last_sent_connect;

  FILE *fp;

  uint32_t file_offset = 0;
  uint32_t file_next_offset = 0;
  uint8_t file_buffer[BLOCK_SIZE];
  PacketTracker tracker[PACKS_PER_BLOCK] = {0};
  int tracker_len = 0;

  double last_sent_close;

  while(state != S_CLOSED_SHOULD_EXIT) {
    switch(state) {
      case S_UNCONNECTED: {
        send_connect(writer_ring, peer, 0, 0);
        last_sent_connect = seconds_since_unspecified_epoch();

        state = S_WAITING_CONNECTION;
      } break;
      
      case S_WAITING_CONNECTION: {
        UDPPacket udp_packet;
        int ret = take_from_reader(reader_ring, &udp_packet);

        if (ret == 0) {
          PacketHeader ph = parse_packet(udp_packet.buf, udp_packet.len, NULL);
          if (ph.type == PACK_TYP_CONNECT_ACK) {
            state = S_OPEN_FILE;
            break;
          }
        }

        double now = seconds_since_unspecified_epoch();
        if ((now - last_sent_connect) > PACKET_RETRY_INTERVAL_SECONDS) {
          send_connect(writer_ring, peer, 0, 0);
          last_sent_connect = now;
        }
      } break;

      case S_OPEN_FILE: {
        fp = fopen("./image.jpg", "rb");
        state = S_CREATE_NEW_BLOCK;
      } break;

      case S_CREATE_NEW_BLOCK: {
        file_offset = file_next_offset;
        int len = fread(file_buffer, 1, BLOCK_SIZE, fp);
        if (len == 0) {
            state = S_SHOULD_CLOSE;
            break;
        }

        file_next_offset += len;

        tracker_len = (len + MAX_PACKET_PAYLOAD_SIZE - 1) / MAX_PACKET_PAYLOAD_SIZE;
        for (int i = 0; i < tracker_len; i++) {
          uint32_t offset = i * MAX_PACKET_PAYLOAD_SIZE;
          uint32_t remaining = len - offset;
          uint32_t length = (remaining > MAX_PACKET_PAYLOAD_SIZE) ? MAX_PACKET_PAYLOAD_SIZE : remaining;
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
        bool has_unconfirmed_packets = false;
        double now = seconds_since_unspecified_epoch();
        int packets_sent_this_iteration = 0;
        for (int i = 0; i < tracker_len; i++) {
          if (tracker[i].confirmed) continue;
          has_unconfirmed_packets = true;

          if ((now - tracker[i].last_sent) > PACKET_RETRY_INTERVAL_SECONDS) {
            PacketTracker t = tracker[i];
            int ret = send_data(writer_ring, peer, file_offset + t.offset, t.length, &file_buffer[t.offset]);

            if (ret == -1) {
              break;
            }

            tracker[i].last_sent = now;

            packets_sent_this_iteration++;
            if (packets_sent_this_iteration > 8) break;
          }
        }

        if (!has_unconfirmed_packets) {
          state = S_CREATE_NEW_BLOCK;
          break;
        }

        state = S_HANDLE_ACKS;
      } break;

      case S_HANDLE_ACKS: {
        UDPPacket udp_packet;
        while(take_from_reader(reader_ring, &udp_packet) != -1) {
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
        last_sent_close = seconds_since_unspecified_epoch();

        state = S_CLOSING_CONNECTION;
      } break;

      case S_CLOSING_CONNECTION: {
        UDPPacket udp_packet;
        int ret = take_from_reader(reader_ring, &udp_packet);

        if (ret == 0) {
          PacketHeader ph = parse_packet(udp_packet.buf, udp_packet.len, NULL);
          if (ph.type == PACK_TYP_CLOSE_ACK) {
            state = S_CLOSE_FILE;
            break;
          }
        }

        double now = seconds_since_unspecified_epoch();
        if ((now - last_sent_close) > PACKET_RETRY_INTERVAL_SECONDS) {
          send_close(writer_ring, peer, 0, 0);
          last_sent_close = now;
        }
      } break;

      case S_CLOSE_FILE: {
        fclose(fp);
        state = S_CLOSED_SHOULD_EXIT;
      } break;

      case S_CLOSED_SHOULD_EXIT: {
        assert(false && "unreachable. state is exit conditon from while");
      } break;
    }
  }
}

typedef enum {
  R_UNCONNECTED = 0,
  R_WAITING_CONNECTION_CONFIRMED,
  R_OPEN_FILE,
  R_READ_DATA,
  R_SEND_CLOSE_ACK,
  R_WAITING_TO_CLOSE,
  R_CLOSE_FILE,
  R_CLOSED_SHOULD_EXIT
} SM_Receiver;

void receiver(UDPRingBuffer *reader_ring, UDPRingBuffer *writer_ring, Peer peer) {
  SM_Receiver state = R_UNCONNECTED;

  FILE *fp;

  double last_sent_close_ack;

  while (state != R_CLOSED_SHOULD_EXIT) {
    switch(state) {
      case R_UNCONNECTED: {
        UDPPacket udp_packet;
        int ret = take_from_reader(reader_ring, &udp_packet);
        if (ret == -1) break;

        PacketHeader ph = parse_packet(udp_packet.buf, udp_packet.len, NULL);
        if (ph.type != PACK_TYP_CONNECT) break;

        send_ack(writer_ring, peer, PACK_TYP_CONNECT_ACK, 0, 0);
        state = R_WAITING_CONNECTION_CONFIRMED;
      } break;

      case R_WAITING_CONNECTION_CONFIRMED: {
        UDPPacket udp_packet;
        int ret = peek_from_reader(reader_ring, &udp_packet);
        if (ret == -1) break;

        PacketHeader ph = parse_packet(udp_packet.buf, udp_packet.len, NULL);
        if (ph.type == PACK_TYP_CONNECT) {
          ret = take_from_reader(reader_ring, NULL);
          assert (ret == 0);

          send_ack(writer_ring, peer, PACK_TYP_CONNECT_ACK, 0, 0);
          break;
        }

        if (ph.type == PACK_TYP_DATA) {
          state = R_OPEN_FILE;
          break;
        }

        // other packet type
        ret = take_from_reader(reader_ring, NULL);

      } break;

      case R_OPEN_FILE: {
        fp = fopen("./recv_image.jpg", "wb");
        fseek(fp, 0, SEEK_SET);
        state = R_READ_DATA;
      } break;

      case R_READ_DATA: {
        UDPPacket udp_packet;
        int ret = take_from_reader(reader_ring, &udp_packet);

        if (ret == -1) break;

        void *data;
        PacketHeader ph = parse_packet(udp_packet.buf, udp_packet.len, &data);

        if (ph.type == PACK_TYP_CLOSE) {
          state = R_SEND_CLOSE_ACK;
          break;
        }

        if (ph.type == PACK_TYP_DATA) {
          fseek(fp, ph.offset, SEEK_SET);
          fwrite(data, 1, ph.length, fp);
          send_data_ack(writer_ring, peer, ph.offset, ph.length);
          break;
        }

      } break;

      case R_SEND_CLOSE_ACK: {
        send_ack(writer_ring, peer, PACK_TYP_CLOSE_ACK, 0, 0);
        last_sent_close_ack = seconds_since_unspecified_epoch();
        state = R_WAITING_TO_CLOSE;
      } break;

      case R_WAITING_TO_CLOSE: {
        UDPPacket udp_packet;
        int ret = take_from_reader(reader_ring, &udp_packet);

        if (ret != -1) {
          PacketHeader ph = parse_packet(udp_packet.buf, udp_packet.len, NULL);

          if (ph.type == PACK_TYP_CLOSE) {
            state = R_SEND_CLOSE_ACK;
            break;
          }
        }

        double now = seconds_since_unspecified_epoch();

        if ((now - last_sent_close_ack) > 3 * PACKET_RETRY_INTERVAL_SECONDS) {
          state = R_CLOSE_FILE;
          break;
        }

      } break;

      case R_CLOSE_FILE: {
        fflush(fp);
        fclose(fp);
        state = R_CLOSED_SHOULD_EXIT;
      } break;

      case R_CLOSED_SHOULD_EXIT: {
        assert(false && "unreachable. state is exit conditon from while");
      } break;
    }
  }
}

Peer find_peer(UDPRingBuffer *reader_ring, UDPRingBuffer *writer_ring, int sock, Endpoint my_endpoint, int id) {
  struct addrinfo *ers_server;
  int ret = getaddrinfo("0.0.0.0", "54321", &addr_hints, &ers_server);
  if (ret != 0) {
    fprintf(stderr, "Could not get addrinfo for ers server\n");
    exit(1);
  }

  struct in_addr ip;
  ip.s_addr = htonl(my_endpoint.addr);

  char ip_string[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &ip, ip_string, sizeof(ip_string));

  char req[128];
  int req_len = snprintf(req, sizeof(req), "REGISTER %d\n%s:%u", id, ip_string, my_endpoint.port);
  add_to_writer(writer_ring, req, req_len, ers_server->ai_addr, ers_server->ai_addrlen);

  req_len = snprintf(req, sizeof(req), "QUERY %d\n", id);
  add_to_writer(writer_ring, req, req_len, ers_server->ai_addr, ers_server->ai_addrlen);

  Peer peer = {0};
  bool found_peer = false;
  while(!found_peer) {
    UDPPacket udp_packet;
    int ret = take_from_reader(reader_ring, &udp_packet);
    if (ret == -1) continue;
    char *buf_ptr = (char*)udp_packet.buf;

    int last = udp_packet.len;
    if (last > MAX_UDP_PACKET_SIZE -1) last = MAX_UDP_PACKET_SIZE - 1;
    buf_ptr[last] = 0;

    char *reply = strsep(&buf_ptr, " ");
    if (strcmp(reply, "ENTRIES") != 0) continue;

    char *id_str = strsep(&buf_ptr, "\n");
    int reply_id = atoi(id_str);

    if (reply_id != id) {
        printf("got entries for other id. my id: %d received: %d\n", id, reply_id);
        continue;
    }

    while (buf_ptr != NULL && buf_ptr[0] != 0) {
        char *payload = strsep(&buf_ptr, "\n");

        char *reply_ip_str = strsep(&payload, ":");
        char *reply_port_str = payload;
        int reply_port = atoi(reply_port_str);

        if (strcmp(reply_ip_str, ip_string) == 0 && reply_port == my_endpoint.port) continue;

        struct addrinfo *peer_addr;
        int ret = getaddrinfo(reply_ip_str, reply_port_str, &addr_hints, &peer_addr);
        if (ret != 0) {
          fprintf(stderr, "Could not get addrinfo for peer\n");
          continue;
        }

        peer = (Peer){
            .fd = sock,
            .addr = peer_addr->ai_addr,
            .addr_len = peer_addr->ai_addrlen,
        };

        found_peer = true;

        printf("Found peer: %s:%d\n", reply_ip_str, reply_port);
        break;
    }

    if (!found_peer) {
        req_len = snprintf(req, sizeof(req), "QUERY %d\n", id);
        add_to_writer(writer_ring, req, req_len, ers_server->ai_addr, ers_server->ai_addrlen);
    }

  }

  return peer;
}


#define LOCAL 1

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s <client|server>\n", argv[0]);
    return -1;
  }

  bool server = false;
  if (strcmp("server", argv[1]) == 0) {
    server = true;
  } else if (strcmp("client", argv[1]) == 0) {
    server = false;
  } else {
    fprintf(stderr, "Usage: %s <client|server>\n", argv[0]);
    return -1;
  }

  int sock = socket(AF_INET, SOCK_DGRAM, 0);

  Endpoint endpoint;
  int res;
  if (LOCAL) {
    res = get_socket_local_endpoint(sock, &endpoint);
  } else {
    res = get_socket_public_endpoint(sock, &endpoint);
  }
  if (res < 0) {
    close(sock);
    exit(1);
  }

  print_endpoint(endpoint);

  int id;
  if (server) {
      srand(time(0));
      id = rand();
      printf("ID: %d\n", id);
  } else {
      printf("What is the ID? ");
      char line[LINE_BUF_SIZE];
      fgets(line, LINE_BUF_SIZE, stdin);
      char *id_str = strtok(line, "\n\r");
      id = atoi(id_str);
  }


  UDPRingBuffer writer_ring = {0};
  writer_ring.data = malloc(sizeof(UDPPacket) * RING_BUFFER_CAP);
  ThreadArgs writer_args = { .ring = &writer_ring, .sock = sock, .should_exit = false };
  sem_init(&writer_ring.sem, 0, 0);
  pthread_t writer_thread;
  pthread_create(&writer_thread, NULL, writer, &writer_args);

  UDPRingBuffer reader_ring = {0};
  reader_ring.data = malloc(sizeof(UDPPacket) * RING_BUFFER_CAP);
  ThreadArgs reader_args = { .ring = &reader_ring, .sock = sock, .should_exit = false };
  sem_init(&reader_ring.sem, 0, RING_BUFFER_CAP - 1);
  pthread_t reader_thread;
  pthread_create(&reader_thread, NULL, reader, &reader_args);

  Peer peer = find_peer(&reader_ring, &writer_ring, sock, endpoint, id);

  if (server) {
      sender(&reader_ring, &writer_ring, peer);
  } else {
      receiver(&reader_ring, &writer_ring, peer);
  }

  atomic_store(&writer_args.should_exit, 1);
  sem_post(&writer_ring.sem);
  pthread_join(writer_thread, NULL);

  close(sock);
}
