#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/types.h>
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

#define LINE_BUF_SIZE 100

typedef enum {
    _RESERVED = 0,
    PACK_INVALID,
    PACK_TYP_ACK,
    PACK_TYP_CONNECT,
    PACK_TYP_CLOSE,
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
    __CONST_SOCKADDR_ARG addr;
    socklen_t addr_len;
} Peer;

void send_ack(Peer peer, uint32_t id, uint32_t ack_id) {
    PacketHeader p = {
        .type = PACK_TYP_ACK,
        ._reserved = 0,
        .checksum = 0,
        .id = id,
        .ack_id = ack_id,
    };

    sendto(peer.fd, &p, sizeof(p), 0, peer.addr, peer.addr_len);
}
void send_connect(Peer peer, uint32_t id, uint32_t ack_id) {
    PacketHeader p = {
        .type = PACK_TYP_CONNECT,
        ._reserved = 0,
        .checksum = 0,
        .id = id,
        .ack_id = ack_id,
    };

    sendto(peer.fd, &p, sizeof(p), 0, peer.addr, peer.addr_len);
}
void send_close(Peer peer, uint32_t id, uint32_t ack_id) {
    PacketHeader p = {
        .type = PACK_TYP_CLOSE,
        ._reserved = 0,
        .checksum = 0,
        .id = id,
        .ack_id = ack_id,
    };

    sendto(peer.fd, &p, sizeof(p), 0, peer.addr, peer.addr_len);
}
void send_data(Peer peer, uint32_t offset, uint32_t length, void *data) {
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

    sendto(peer.fd, buffer, sizeof(PacketHeader) + length, 0, peer.addr, peer.addr_len);
}
void send_data_ack(Peer peer, uint32_t offset, uint32_t length) {
    PacketHeader p = {
        .type = PACK_TYP_DATA_ACK,
        ._reserved = 0,
        .checksum = 0,
        .offset = offset,
        .length = length,
    };

    sendto(peer.fd, &p, sizeof(p), 0, peer.addr, peer.addr_len);
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
    bool confirmed;
} PacketTracker;

void sender(Peer peer) {
    send_connect(peer, 0, 0);

    char buf[1000];
    ssize_t bytes_recv = recvfrom(peer.fd, &buf, sizeof(buf), 0, NULL, NULL); 
    PacketHeader ph_ack = parse_packet(buf, bytes_recv, NULL);
    if (ph_ack.type != PACK_TYP_ACK) {
        printf("did not get ack");;
    }

    FILE *fp = fopen("./image.jpg", "rb");

    uint32_t filebuffer_offset = 0;
    uint32_t filebuffer_offset_next = 0;
    uint8_t filebuffer[BLOCK_SIZE];
    PacketTracker pt[PACKS_PER_BLOCK] = {0};
    int pt_idx = 0;
    int pt_cap = 0;
    bool exit = false;
    while (!exit) {

        // HANDLE ACKS AND PACKETS RECEIVED
        while((bytes_recv = recvfrom(peer.fd, &buf, sizeof(buf), MSG_DONTWAIT, NULL, NULL)) != (ssize_t)-1) {
            PacketHeader ph = parse_packet(buf, bytes_recv, NULL);
            if (ph.type == PACK_TYP_DATA_ACK) {
                for (int i = 0; i < pt_idx; i++) {
                    if (pt[i].offset + filebuffer_offset == ph.offset) {
                        pt[i].confirmed = true;
                    }
                }
            }
        }

        // CHECK IF NEW BLOCK IS NEEDED
        bool should_new_block = true;
        for (int i = 0; i < pt_idx; i++) {
            if (!pt[i].confirmed) {
                should_new_block = false;
                break;
            }
        }
        if (pt_idx < pt_cap) should_new_block = false;

        // MOVE TO NEW BLOCK
        if (should_new_block) {
            printf("new block\n");
            filebuffer_offset = filebuffer_offset_next;
            int len = fread(filebuffer, 1, BLOCK_SIZE, fp);
            if (len == 0) {
                exit = true;
                break;
            }
            filebuffer_offset_next += len;
            pt_idx = 0;
            pt_cap = (len + MAX_PACKET_PAYLOAD_SIZE - 1) / MAX_PACKET_PAYLOAD_SIZE;
        }

        // CREATE NEW PACKET TRACKER
        if (pt_idx < pt_cap) {
            uint32_t offset = pt_idx * MAX_PACKET_PAYLOAD_SIZE;
            uint32_t remaining = filebuffer_offset_next - filebuffer_offset - offset;
            uint32_t length = (remaining > MAX_PACKET_PAYLOAD_SIZE) ? MAX_PACKET_PAYLOAD_SIZE : remaining;
            pt[pt_idx] = (PacketTracker){
                .offset = offset,
                .length = length,
                .confirmed = false,
            };
            pt_idx++;
        }

        // SEND UNCONFIRMED PACKETS
        for (int i = 0; i < pt_idx; i++) {
            if (!pt[i].confirmed) {
                send_data(peer, pt[i].offset + filebuffer_offset, pt[i].length, filebuffer + pt[i].offset);
            }
        }
    }

    send_close(peer, 0, 0);
}

void client(Peer peer) {
    char buf[1000];
    ssize_t bytes_recv = recvfrom(peer.fd, &buf, sizeof(buf), 0, NULL, NULL);
    PacketHeader ph_connect = parse_packet(buf, bytes_recv, NULL);
    if (ph_connect.type != PACK_TYP_CONNECT) {
        printf("did not get connect");;
    }

    send_ack(peer, 0, 0);

    FILE *fp = fopen("./recv_image.jpg", "wb");
    fseek(fp, 0, SEEK_SET);
    bool should_exit = false;
    while (!should_exit) {
      uint8_t buf[STUN_BUFFER_SIZE + 1];
      ssize_t bytes_recv = recvfrom(peer.fd, &buf, sizeof(buf), 0, NULL, NULL);

      void *data;
      PacketHeader ph = parse_packet(buf, bytes_recv, &data);

      switch (ph.type) {
          case PACK_TYP_CLOSE: {
            should_exit = true;
          } break;

          case PACK_TYP_DATA: {
            fseek(fp, ph.offset, SEEK_SET);
            fwrite(data, 1, ph.length, fp);
            send_data_ack(peer, ph.offset, ph.length);
          } break;

          default:
              break;
      }

    }

    fflush(fp);
}

Peer find_peer(int sock, Endpoint my_endpoint, int id) {
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
  sendto(
      sock,
      req,
      req_len,
      0,
      ers_server->ai_addr,
      ers_server->ai_addrlen
  );

  req_len = snprintf(req, sizeof(req), "QUERY %d\n", id);
  sendto(
      sock,
      req,
      req_len,
      0,
      ers_server->ai_addr,
      ers_server->ai_addrlen
  );

  Peer peer = {0};
  bool found_peer = false;
  while(!found_peer) {
    char buf[1000];
    ssize_t bytes_recv = recvfrom(sock, &buf, sizeof(buf) - 1, 0, NULL, NULL); 
    buf[bytes_recv] = 0;
    char *buf_ptr = buf;

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
        sendto(
            sock,
            req,
            req_len,
            0,
            ers_server->ai_addr,
            ers_server->ai_addrlen
        );
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

  Peer peer = find_peer(sock, endpoint, id);

  if (server) {
      sender(peer);
  } else {
      client(peer);
  }


  close(sock);
}
