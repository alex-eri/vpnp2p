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

#include "map.h"

mac_t mac_broadcast = {255,255,255,255,255,255};


// https://stackoverflow.com/a/38606527/2101808

typedef struct service_data {
    uv_pipe_t * tun;
    uv_udp_t *socket;
    char * stun_host;
    char * stun_port;
    addr_t extaddr;
    addr_t intaddr;
    list_t peers;
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

void on_write(uv_write_t* req, int status) {
    if (status) {
        fprintf(stderr, "Send error: %s\n", uv_strerror(status));
        return;
    }
    free(req);
}

void on_send(uv_udp_send_t *req, int status) {
    if (status) {
        fprintf(stderr, "Send error: %s\n", uv_strerror(status));
        return;
    }
    free(req);
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
           //memcpy(&(data->extaddr),&addr,sizeof(struct sockaddr));
           data->extaddr.addr_in = addr;
       }
       pointer += (sizeof(struct STUNAttributeHeader) + ntohs(header->length));
   }
}

void fprintf_ipport(FILE *fd, struct sockaddr_in *addr) {
    char extaddr[17] = { 0 };
    uv_ip4_name(addr, extaddr, 16);
    fprintf(fd, "\n%s:%d", extaddr, ntohs(addr->sin_port));
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
    mac_t * mac;
    uint16_t type;
    memcpy(&type, buf->base,2);

    fprintf_ipport(stderr, (struct sockaddr_in*)addr);

    switch(type) {

    case 0x0101 :
        stun_on_read(handle, &mbuf);
        fprintf_ipport(stderr, (struct sockaddr_in *)&data->extaddr);
        break;

    case 0x7575 :
        mac = (mac_t *)(buf->base + 8);
        map_insert(&(data->peers), mac, (addr_t*) addr);
        map_insert(&(data->peers), &mac_broadcast, (addr_t*) addr);
        mbuf = uv_buf_init(buf->base+2, nread-2);
        //uv_write_t *req=malloc(sizeof (uv_write_t));
        MALLOCCLEAR(uv_write_t, req);
        uv_write(req, (uv_stream_t *)data->tun, &mbuf, 1, on_write);

        break;
    }
    free(buf->base);
}


void stun_on_resolved(uv_getaddrinfo_t* req, int status, struct addrinfo* res) {
    if (status < 0) {
        fprintf(stderr, "getaddrinfo callback error %s\n", uv_err_name(status));
        uv_close((uv_handle_t*) req, NULL);
        return;
    }
    struct sockaddr * addrp;
    do {
        if (res->ai_addr->sa_family == AF_INET) {
            addrp = res->ai_addr;
            break;
        }
    } while( res->ai_next );
    //struct sockaddr * addr = malloc(sizeof(struct sockaddr));
    MALLOCCLEAR(struct sockaddr, addr);
    memcpy(addr, addrp, sizeof(struct sockaddr));
    char extaddr[17] = { 0 };
    uv_ip4_name((struct sockaddr_in *)addr, extaddr, 16);
    //uv_udp_send_t * udp_req= malloc(sizeof (uv_udp_send_t));
    MALLOCCLEAR(uv_udp_send_t, udp_req);
    udp_req->data = req->data;
    service_data_t * data = req->data;
    struct STUNMessageHeader request;
    request.type = htons(0x0001);
    request.length = htons(0x0000);
    request.cookie = htonl(0x2112A442);
    for (int index = 0; index < 3; index++)
    {
        srand((unsigned int) time(0));
        request.identifier[index] = rand();
        data->stun_identifier[index] = request.identifier[index];
    }
    uv_buf_t buf = uv_buf_init( (char * )&request , sizeof(struct STUNMessageHeader));
    uv_udp_send(udp_req, data->socket, &buf, 1, addr, on_send);
    uv_freeaddrinfo(res);
}


void stun(uv_timer_t * handle) {
    uv_getaddrinfo_t * resolver = malloc(sizeof (uv_getaddrinfo_t));
    service_data_t * data = (service_data_t *) handle->data;
    resolver->data = data;
    struct addrinfo hints;
    hints.ai_family = PF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    hints.ai_flags = 0;
    char * host = data->stun_host;
    char * port = data->stun_port;
    uv_getaddrinfo(handle->loop, resolver, stun_on_resolved, host, port, &hints);
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
    fcntl(fd, F_SETFL, O_NONBLOCK );
    strcpy(dev, ifr.ifr_name);
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    ifr.ifr_flags = IFF_UP | IFF_BROADCAST;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    ioctl(sock, SIOCSIFFLAGS, &ifr);
    return fd;
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
    uv_udp_send_t * udp_req;

    char * message = malloc(nread + 2);
    memset(message, 0x75, 2);
    memcpy(message + 2, buf->base, nread);
    uv_buf_t message_buf = uv_buf_init(message, nread + 2);

    mac_t * mac = (mac_t * )buf->base;
    mac_map * peer = map_find(&(data->peers), mac, NULL);

    while (peer) {
        udp_req = malloc(sizeof (uv_udp_send_t));
        memset(udp_req, 0, sizeof (uv_udp_send_t));
        uv_udp_send(udp_req, data->socket, &message_buf, 1, &(peer->addr.addr), on_send);
        // fprintf_ipport(stderr,&(peer->addr.addr_in));
        if (peer->next) {
            peer = map_find(&(data->peers), mac, peer->next);
        } else {
            break;
        }
    }

    free(message);
    free(buf->base);
}

void read_stdin(uv_stream_t *stream, ssize_t nread, const uv_buf_t* buf)
{
  if (nread < 0) {
    uv_close((uv_handle_t*)stream, NULL);
    return;
  }
  service_data_t *data = stream->data;

  char * tokp;
  char * class = strtok_r (buf->base, " ", &tokp);
  char * cmd = strtok_r (NULL, " ", &tokp);

  if (class == NULL && (strncmp("help", class, 4)==0)) {
      fprintf(stderr, "config stun ip:port\npeer add ip:port\npeer list\nshow\nhelp");
  }
  else if (strncmp("config", class, 6)==0) {
      if (cmd == NULL) {}
      else if (strncmp("stun", cmd, 6)==0) {
          char *ip = strtok_r (NULL, " :", &tokp);
          char *port = strtok_r (NULL, " :", &tokp);
          free(data->stun_host);
          free(data->stun_port);
          data->stun_host = strdup(ip);
          data->stun_port = strdup(port);
          uv_timer_t handle;
          handle.data = data;
          handle.loop = stream->loop;
          stun(&handle);
      }
  }


  else if  (strncmp("peer", class, 4)==0) {
      if (cmd == NULL) {}
      else if (strncmp("add", cmd, 3)==0) {
          char *ip = strtok_r (NULL, " :", &tokp);
          char *port = strtok_r (NULL, " :", &tokp);

          addr_t addr;
          uv_ip4_addr(ip, atoi(port), &(addr.addr_in));
          map_insert(&(data->peers), &mac_broadcast, &addr);
      } else if (strncmp("list", cmd, 4)==0) {
          mac_map * peer = data->peers.items;
          while (peer) {

              if (memcmp(&(peer->mac), &mac_broadcast, 6)==0) {
                fprintf_ipport(stdout, &(peer->addr.addr_in));
                fprintf(stdout," %ld ", peer->expire - time(0));
              }
              peer = peer->next;
          }

      }

  }

  else if (strncmp("show", class, 4)==0) {
      fprintf(stdout,"\nexternal address: ");
      fprintf_ipport(stdout, (struct sockaddr_in *)&(data->extaddr));
      fprintf(stdout,"\nbind address: ");
      fprintf_ipport(stdout, (struct sockaddr_in *)&(data->intaddr));
      fprintf(stdout,"\n");
  }

}


int main()
{
    int r;
    uv_loop_t *loop = uv_default_loop();

//    uv_pipe_t * tun_pipe =  malloc(sizeof (uv_pipe_t));
//    uv_udp_t * recv_socket = malloc(sizeof (uv_udp_t));
//    service_data_t * data = malloc(sizeof (service_data_t));
//    uv_pipe_t * stdin_pipe = malloc(sizeof (uv_pipe_t));
    MALLOCCLEAR(uv_pipe_t, tun_pipe);
    MALLOCCLEAR(uv_udp_t, recv_socket);
    MALLOCCLEAR(service_data_t, data);
    MALLOCCLEAR(uv_pipe_t, stdin_pipe);

    stdin_pipe->data = data;
    uv_pipe_init(uv_default_loop(), stdin_pipe, 0);
    uv_pipe_open(stdin_pipe, 0);
    uv_read_start((uv_stream_t *)stdin_pipe, alloc_buffer, read_stdin);
    int tap;
    char * dev = malloc(IFNAMSIZ);
    for (int i = 0; ; i++) {
        sprintf(dev,"tapp2p%d",i);
        //strncpy(dev, "tapp2p", IFNAMSIZ);
        tap = tun_alloc(dev);
        if (tap < 0 && i==5)
            return 1;
        if (tap > 3) break;
    }
    uv_pipe_init(loop, tun_pipe, 0);
    tun_pipe->data = data;
    uv_pipe_open(tun_pipe, tap);
    uv_stream_t* stream = (uv_stream_t*)tun_pipe;
    uv_read_start(stream, alloc_buffer, packet_on_tap);
    recv_socket->data = data;
    data->tun = tun_pipe;
    data->socket = recv_socket;
    data->stun_host = strdup("stun.l.google.com");
    data->stun_port = strdup("19302");
    data->peers.items = NULL;
    uv_udp_init(loop, recv_socket);
    for (int i = 0; ; i++) {
        if (i==5)
            return 2;
        uv_ip4_addr("0.0.0.0", 7785+i, &(data->intaddr.addr_in));
        printf("%d\n",data->intaddr.addr_in.sin_port);
        fprintf_ipport(stderr,&(data->intaddr.addr_in));
        if (uv_udp_bind(recv_socket, &(data->intaddr.addr), 0)==0) break;
    }
    uv_udp_recv_start(recv_socket, alloc_buffer, on_read);
    uv_timer_t stun_timer;
    stun_timer.data = data;
    uv_timer_init(loop, &stun_timer);
    uv_timer_start(&stun_timer, stun, 0, 120000);
    r = uv_run(loop, UV_RUN_DEFAULT);
    return r;
}
