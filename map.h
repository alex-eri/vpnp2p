#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>

#ifndef MACMAP_H
#define MACMAP_H 1

#define TIMEOUT 120

typedef struct mac_s {
   unsigned char bytes[6];
} mac_t;


typedef union {
    struct sockaddr addr;
    struct sockaddr_in addr_in;
} addr_t;

typedef struct mac_map_s {
    struct mac_map_s* next;
    time_t expire;
    mac_t mac;
    addr_t addr;
} mac_map;


void map_remove(mac_map * peers, mac_t * mac, addr_t * addr, bool _and) ;

#define map_remove_mac(peers, mac) map_remove(peers, mac, NULL, 0)
#define map_remove_addr(peers, addr) map_remove(peers, NULL, addr, 0)

mac_map * map_insert(mac_map * peers, mac_t * mac, addr_t * addr );
mac_map * map_find(mac_map * peers, mac_t * mac);

#define puint16cmp(p,b) (uint16_t)&(p) == htons(b)

#endif
