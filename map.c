#include "map.h"

mac_map * map_insert(mac_map * peers, mac_t * mac, addr_t * addr ){
    mac_map * new = malloc(sizeof (mac_map));
    new->next = peers;
    peers = new;
    new->mac = * mac;
    new->addr = * addr;
    new->expire = time(0) + TIMEOUT;
    map_remove(new->next, &(new->mac), &(new->addr), true);
    return new;
}

mac_map * map_remove_next(mac_map* prev) {
    mac_map * peer = prev->next;
    prev->next = peer->next;
    free(peer);
    return prev;
}

#define CHECK(p,v) (v != NULL && memcmp(&(p->v), v, sizeof (* v)) ==0 )

void map_remove(mac_map* peers, mac_t *mac, addr_t *addr, bool _and) {
    mac_map * p = peers;
    mac_map pstart;
    mac_map * prev = &pstart;
    pstart.next = peers;
    time_t now = time(0);
    while ( p ) {

        if (    ( _and &&  ( CHECK(p, mac) && CHECK(p, addr) )) ||
                ( !_and && ( CHECK(p, mac) || CHECK(p, addr) )) ||
                p->expire < now
                ) {
            p = map_remove_next(prev);
        }
        prev = p;
        p=p->next;
    };
}


mac_map * map_find(mac_map* peers, mac_t *mac) {
    mac_map * p = peers;
    mac_map pstart;
    mac_map * prev = &pstart;
    pstart.next = peers;
    time_t now = time(0);
    while ( p ) {
        if ( p->expire < now) {
            p = map_remove_next(prev);
        } else if ( CHECK(p, mac) ) {
            return p;
        }
        prev = p;
        p=p->next;
    } ;
    return NULL;
}
