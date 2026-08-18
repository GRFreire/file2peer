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
  
  out_endpoint->port = ntohs(addr.sin_port);
  out_endpoint->addr = ntohl(addr.sin_addr.s_addr);
  return 0;
}

#define LINE_BUF_SIZE 100
#define PACKET_MAGIC 0xCAFE
#define PACKET_BUF_SIZE 1500


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

  Endpoint public_endpoint;
  int res = get_socket_public_endpoint(sock, &public_endpoint);
  if (res < 0) {
    close(sock);
    exit(1);
  }

  Endpoint local_endpoint;
  res = get_socket_local_endpoint(sock, &local_endpoint);
  if (res < 0) {
    close(sock);
    exit(1);
  }

  printf("Public ");
  print_endpoint(public_endpoint);

  printf("Local ");
  print_endpoint(local_endpoint);

  printf("Where sould I connect (IP:PORT)? ");
  char line[LINE_BUF_SIZE];
  fgets(line, LINE_BUF_SIZE, stdin);
  char *ip = strtok(line, ":");
  char *port = strtok(NULL, "\n\r");

  printf("You have entered ip %s and port %s.\n", ip, port);

  struct addrinfo *peer_addr;
  int ret = getaddrinfo(ip, port, &addr_hints, &peer_addr);
  if (ret != 0) {
    fprintf(stderr, "Could not get addrinfo for STUN server\n");
    return -1;
  }

  if (server) {
    char *connect_buf = "connect";
    sendto(sock, connect_buf, strlen(connect_buf), 0, peer_addr->ai_addr, peer_addr->ai_addrlen);

    char buf[1000];
    ssize_t bytes_recv = recvfrom(sock, &buf, sizeof(buf), 0, NULL, NULL);
    if (strncmp("ack", buf, bytes_recv) != 0) {
      printf("not received ack\n");
    }

    char *data1 = "data1";
    char *data2 = "data2";
    char *data3 = "exit";
    sendto(sock, data1, strlen(data1), 0, peer_addr->ai_addr, peer_addr->ai_addrlen);
    sendto(sock, data2, strlen(data2), 0, peer_addr->ai_addr, peer_addr->ai_addrlen);
    sendto(sock, data3, strlen(data3), 0, peer_addr->ai_addr, peer_addr->ai_addrlen);
  } else {
    char buf[1000];
    ssize_t bytes_recv = recvfrom(sock, &buf, sizeof(buf), 0, NULL, NULL);
    if (strncmp("connect", buf, bytes_recv) != 0) {
      printf("not received connect\n");
    }

    char *ack_buf = "ack";
    sendto(sock, ack_buf, strlen(ack_buf), 0, peer_addr->ai_addr, peer_addr->ai_addrlen);

    bool should_exit = false;
    while (!should_exit) {
      uint8_t buf[STUN_BUFFER_SIZE + 1];
      ssize_t bytes_recv = recvfrom(sock, &buf, sizeof(buf), 0, NULL, NULL);
      buf[bytes_recv] = 0;
      printf("%s\n", buf);
      if (strcmp((char *)buf, "exit") == 0) {
        should_exit = true;
      }
    }
  }

  close(sock);
}
