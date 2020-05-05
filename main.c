#include <stdio.h>
#include <uv.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>

#include <fcntl.h> // for open
#include <unistd.h> // for close
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>

// https://stackoverflow.com/a/38606527/2101808

typedef struct peer_s {
    struct peer_s * next;
    struct peer_s * prev;
    union {
        struct sockaddr addr;
        struct sockaddr_in addr_in;
    };
    union {
        char mac[6];
    };
} peer_t;

typedef struct service_data {
    uv_pipe_t * tun;
    uv_udp_t *socket;
    char * stun_host;
    char * stun_port;
    struct sockaddr extaddr;
    peer_t *peers;
    ssize_t peers_count;
    unsigned int stun_identifier[3];

} service_data_t;

#pragma pack(push, 1)

// RFC 5389 Section 6 STUN Message Structure
struct STUNMessageHeader
{
    uint16_t type;
    uint16_t length;
    uint32_t cookie;
    uint32_t identifier[3];
};

#define XOR_MAPPED_ADDRESS_TYPE 0x0020

// RFC 5389 Section 15 STUN Attributes
struct STUNAttributeHeader
{
    uint16_t type;
    uint16_t length;
};

#define IPv4_ADDRESS_FAMILY 0x01
#define IPv6_ADDRESS_FAMILY 0x02

// RFC 5389 Section 15.2 XOR-MAPPED-ADDRESS
struct STUNXORMappedIPv4Address
{
    uint8_t reserved;
    uint8_t family;
    uint16_t port;
    uint32_t address;
};

#pragma pack(pop)

void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
  buf->base = malloc(suggested_size);
  buf->len = suggested_size;
}

void on_send(uv_udp_send_t *req, int status) {
    if (status) {
        fprintf(stderr, "Send error: %s\n", uv_strerror(status));

        char addr[17] = { 0 };
        uv_ip4_name((const struct sockaddr_in*) &(req->addr), addr, 16);
        fprintf(stderr, "addr %s\n", addr);
        return;
    }
}


void stun_on_read(uv_udp_t *handle, const uv_buf_t *buf) {
   char* pointer = buf->base;
   struct STUNMessageHeader* response = (struct STUNMessageHeader*) buf->base;

   service_data_t* data = (service_data_t*) handle->data;

   for (int index = 0; index < 3; index++)
       if (data->stun_identifier[index] != response->identifier[index])
           return ;

   pointer += sizeof(struct STUNMessageHeader);
   while (pointer < buf->base + buf->len)
   {
       struct STUNAttributeHeader* header = (struct STUNAttributeHeader*) pointer;
       if (header->type == htons(XOR_MAPPED_ADDRESS_TYPE)) {
           pointer += sizeof(struct STUNAttributeHeader);
           struct STUNXORMappedIPv4Address* xorAddress = (struct STUNXORMappedIPv4Address*) pointer;
           struct sockaddr_in addr ;
           if (xorAddress->family == IPv4_ADDRESS_FAMILY) {
               addr.sin_family = AF_INET;
           }
           else if (xorAddress->family == IPv6_ADDRESS_FAMILY)
               addr.sin_family = AF_INET6;

           addr.sin_addr.s_addr = (xorAddress->address)^htonl(0x2112A442);
           addr.sin_port = (xorAddress->port)^htons(0x2112);

           memcpy(&(data->extaddr),&addr,sizeof(struct sockaddr));

       }
       pointer += (sizeof(struct STUNAttributeHeader) + ntohs(header->length));
   }
}


void on_read(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf, const struct sockaddr *addr, unsigned flags) {
    if (nread < 0) {
        fprintf(stderr, "Read error %s\n", uv_err_name(nread));
        uv_close((uv_handle_t*) handle, NULL);
        free(buf->base);
        return;
    }
    if (nread == 0) {
        free(buf->base);
        return;
    }
    uv_buf_t mbuf = uv_buf_init(buf->base, nread);
    service_data_t* data = (service_data_t*) handle->data;
    if (memcmp(buf->base, "\01\01", 2) == 0) {
        fprintf(stderr, "stun_on_read\n");
        stun_on_read(handle, &mbuf);
        struct sockaddr_in *addr = (struct sockaddr_in *)&data->extaddr;
        char extaddr[17] = { 0 };
        uv_ip4_name(addr, extaddr, 16);
        fprintf(stderr, "ext %s:%d\n", extaddr, addr->sin_port);
    }
    free(buf->base);
}


void stun_on_resolved(uv_getaddrinfo_t* req, int status, struct addrinfo* res) {
    if (status < 0) {
        fprintf(stderr, "getaddrinfo callback error %s\n", uv_err_name(status));
        uv_close((uv_handle_t*) req, NULL);
        return;
    }
    fprintf(stderr, "getaddrinfo");
    struct sockaddr *addrp;
    do {
        if (res->ai_addr->sa_family == AF_INET) {
            addrp = res->ai_addr;
            break;
        }
    } while( res->ai_next );
    struct sockaddr *addr = malloc(sizeof(struct sockaddr));
    memcpy(addr, addrp, sizeof(struct sockaddr));
    char extaddr[17] = { 0 };
    uv_ip4_name((struct sockaddr_in *)addr, extaddr, 16);
    fprintf(stderr, "ext %s:%d\n", extaddr, ((struct sockaddr_in *)addr)->sin_port);
    uv_udp_send_t *udp_req= malloc(sizeof (udp_req));
    memset(udp_req,0, sizeof (udp_req));
    udp_req->data = req->data;
    service_data_t *data = req->data;
    struct STUNMessageHeader *request = malloc(sizeof (struct STUNMessageHeader));
    request->type = htons(0x0001);
    request->length = htons(0x0000);
    request->cookie = htonl(0x2112A442);
    for (int index = 0; index < 3; index++)
    {
        srand((unsigned int) time(0));
        request->identifier[index] = rand();
        data->stun_identifier[index] = request->identifier[index];
    }
    uv_buf_t buf = uv_buf_init( (char*)request , sizeof(struct STUNMessageHeader));
    uv_udp_send(udp_req, data->socket, &buf, 1, addr, on_send);
    uv_freeaddrinfo(res);
}


void stun(uv_timer_t *handle) {
    uv_getaddrinfo_t resolver;
    service_data_t* data = (service_data_t*) handle->data;
    resolver.data = data;
    struct addrinfo hints;
    hints.ai_family = PF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    hints.ai_flags = 0;
    char * host = data->stun_host;
    char * port = data->stun_port;
    fprintf(stderr, "stun host %s:%s\n", host, port);
    uv_getaddrinfo(handle->loop, &resolver, &stun_on_resolved, host, port, &hints);
}

int tun_alloc(char *dev) {
    struct ifreq ifr;
    int fd, err;
    char *clonedev = "/dev/net/tun";
    if( (fd = open(clonedev, O_RDWR)) < 0 ) return fd;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;//| IFF_MULTI_QUEUE;   /* IFF_TUN or IFF_TAP, plus maybe IFF_NO_PI */

    if (*dev) strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    if( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ) {
      close(fd);
      return err;
    }
    //fcntl(fd, F_SETFL, O_NONBLOCK | O_ASYNC);
    strcpy(dev, ifr.ifr_name);
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    ifr.ifr_flags = IFF_UP | IFF_BROADCAST;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    ioctl(sock, SIOCSIFFLAGS, &ifr);
    return fd;
}


peer_t * peer_insert(peer_t *peer, char* mac, struct sockaddr addr) {
    peer_t * new = malloc(sizeof (peer_t));
    memcpy(new->mac, mac, 6);
    memcpy(&(new->addr), &addr, sizeof(struct sockaddr));
    new->prev = peer;
    new->next = peer->next;
    peer->next = new;
    return new;
}

void peer_remove(peer_t *peer){
    peer_t *next = peer->next;
    if (peer->prev)
        peer->prev->next = peer->next;
    free(peer);
    peer = next;
}

peer_t *peer_find(peer_t *peer, char* mac) {
    while (peer) {
        if (memcmp(peer->mac, mac, 6)==0) return peer;
        peer = peer->next;
    } ;
    return NULL;
}


void packet_on_tap(uv_stream_t* handle, ssize_t nread, const uv_buf_t* buf){
    service_data_t* data = (service_data_t*) handle->data;
    if (nread < 0) {
        fprintf(stderr, "Read error %s\n", uv_err_name(nread));
        uv_close((uv_handle_t*) handle, NULL);
        free(buf->base);
        return;
    }
    if (nread == 0) {
        free(buf->base);
        return;
    }
    //uv_udp_send_t udp_req;
    //peer_t *peer = data->peers;
//    if ( memcmp(buf->base, "\xff\xff\xff\xff\xff\xff", 6)==0 ) {
//        while (peer) {
//            udp_req = malloc(sizeof (uv_udp_send_t));
//            uv_udp_send(udp_req, data->socket, buf, 1, &(peer->addr), on_send);
//            peer = peer->next;
//        };
//    }
//    peer = peer_find(data->peers, buf->base);
//    if (peer) {
//        uv_udp_send(udp_req, data->socket, buf, 1, &(peer->addr), on_send);
//    }
    for (size_t i = 0; i != 12; ++i)
        fprintf(stderr, "%02x", (unsigned char)buf->base[i]);
    free(buf->base);
}

int main()
{
    uv_loop_t *loop = uv_default_loop();
    uv_pipe_t * tun_pipe =  malloc(sizeof (uv_pipe_t));
    uv_udp_t * recv_socket = malloc(sizeof (uv_udp_t));
    service_data_t *data = malloc(sizeof (service_data_t));
    char * dev = malloc(IFNAMSIZ);
    strncpy(dev,"tapp2p",IFNAMSIZ);
    int tap = tun_alloc(dev);
    fprintf(stderr, "tap %s %d\n", dev, tap);
    if (tap < 0) return tap;
    uv_pipe_init(loop, tun_pipe, 0);
    tun_pipe->data = data;
    uv_pipe_open(tun_pipe, tap);
    uv_stream_t* stream = (uv_stream_t*)tun_pipe;
    fprintf(stderr, "stream %p\n", stream);
    uv_read_start(stream, alloc_buffer, packet_on_tap);
    recv_socket->data = data;
    data->tun = tun_pipe;
    data->socket = recv_socket;
    data->stun_host = "stun.l.google.com";
    data->stun_port = "19302";
    uv_udp_init(loop, recv_socket);
    struct sockaddr_in recv_addr;
    uv_ip4_addr("0.0.0.0", 7785, &recv_addr);
    uv_udp_bind(recv_socket, (struct sockaddr *)&recv_addr, 0);
    uv_udp_recv_start(recv_socket, alloc_buffer, on_read);
    uv_timer_t stun_timer;
    stun_timer.data = data;
    uv_timer_init(loop, &stun_timer);
    uv_timer_start(&stun_timer, stun, 0, 120*000);
    fprintf(stderr, "socket %p\n", recv_socket);
    int r = uv_run(loop, UV_RUN_DEFAULT);
    fprintf(stderr, "uv_run = %d\n", r);
    return r;
}
