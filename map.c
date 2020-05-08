#include "map.h"


void map_insert(list_t * peers, mac_t * mac, addr_t * addr ){
    mac_map * new = malloc(sizeof (mac_map));
    new->next = peers->items;
    new->mac = * mac;
    new->addr = * addr;
    new->expire = time(0) + TIMEOUT;
    map_remove(peers, &(new->mac), &(new->addr), true);
    peers->items = new;
}


#define CHECK(p,v) (v != NULL && memcmp(&(p->v), v, sizeof (* v)) ==0 )

void map_remove(list_t * peers, mac_t *mac, addr_t *addr, bool _and) {
    mac_map * p = peers->items;
    mac_map * prev = NULL;
    time_t now = time(0);

    while ( p ) {
        if (    ( _and &&  ( CHECK(p, mac) && CHECK(p, addr) )) ||
                ( !_and && ( CHECK(p, mac) || CHECK(p, addr) )) ||
                p->expire < now
                ) {
            if (prev) {
                prev->next = p->next;
            }
            else {
                peers->items = p->next;
            }
            prev=p;
            p=p->next;
            free(prev);
        } else {
            prev = p;
            p=p->next;
        }
    }
}


mac_map *  map_find(list_t * peers, mac_t *mac, mac_map * prev) {
    mac_map * p ;

    if (prev) {
        p = prev;
    } else {
        p = peers->items;
    }
    time_t now = time(0);

    while ( p ) {
        if ( p->expire < now ) {
            if (prev) {
                prev->next = p->next;
            }
            else {
                peers->items = p->next;
            }
            prev=p;
            p=p->next;
            free(prev);
        } else if ( CHECK(p, mac) ) {
            return p;
        } else {
            prev = p;
            p=p->next;
        }
    };

    return NULL;
}
