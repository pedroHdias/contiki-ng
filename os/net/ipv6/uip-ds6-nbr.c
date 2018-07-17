/*
 * Copyright (c) 2013, Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *
 */

/**
 * \addtogroup uip
 * @{
 */

/**
 * \file
 *    IPv6 Neighbor cache (link-layer/IPv6 address mapping)
 * \author Mathilde Durvy <mdurvy@cisco.com>
 * \author Julien Abeille <jabeille@cisco.com>
 * \author Simon Duquennoy <simonduq@sics.se>
 *
 */

#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include "lib/list.h"
#include "net/link-stats.h"
#include "net/linkaddr.h"
#include "net/packetbuf.h"
#include "net/ipv6/uip-ds6.h"
#include "net/ipv6/uip-ds6-nbr.h"
#include "net/ipv6/uip-nd6.h"
#include "net/routing/routing.h"

#include <stdbool.h>
#include <stdio.h>
#include <time.h>
#include "sys/clock.h"
#include "sys/stimer.h"
#include "contiki.h"
#include "random.h"
#include "net/netstack.h"
#include "net/ipv6/simple-udp.h"
#include "net/ipv6/uiplib.h"
#include "dev/leds.h"

/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "IPv6 Nbr"
#define LOG_LEVEL LOG_LEVEL_INFO

// Configuração Sender-Listener --> Vitabox
#define WITH_SERVER_REPLY  0
#define UDP_CLIENT_PORT 8000
#define UDP_SERVER_PORT 10001
//estrutura para conexão UDP
static struct simple_udp_connection udp_conn_nbr;
//endereço do servidor (vitabox)
uip_ipaddr_t server_ipaddr;
static char *message_nbr;
//array de nós registados na BD local do BR (variável partilhada entre ficheiros) max 10 vizinhos
char removed_motes_nbr[6][40];
//contador para incrementar posição no array
int cont_nbr=0;
//moteIP a comparar ao adicionar vizinho
char nodeip[40];

NBR_TABLE_GLOBAL(uip_ds6_nbr_t, ds6_neighbors);

/*---------------------------------------------------------------------------*/
//método para verificar se nó já foi aprovado no registo de vizinhos
bool is_node_removed_motes_nbr(char *addr){
  for (int i = 0; i < 6; i ++){
    clock_delay(400);
    LOG_INFO("COMPARING NODE IN NBR-- %s -- TO LOCAL DATABASE -- %s\n", addr, removed_motes_nbr[i]);
    if (strcmp(removed_motes_nbr[i],addr) == 0){
      //se encontrar o nodeid, retorna true
      LOG_INFO("NODE FOUND IN LOCAL DATABASE (NBR) ---- %s\n", removed_motes_nbr[i]);
      return true;
    } 
  }
  //se não encontrar o nodeid, retorna false
  LOG_INFO("NODE NOT FOUND IN LOCAL DATABASE (NBR)\n");
  return false;
}
/*---------------------------------------------------------------------------*/
uip_ds6_nbr_t *
uip_ds6_nbr_add(const uip_ipaddr_t *ipaddr, const uip_lladdr_t *lladdr,
                uint8_t isrouter, uint8_t state, nbr_table_reason_t reason,
                void *data)
{
  leds_off(LEDS_ALL);
  leds_toggle(LEDS_BLUE);
   //nó entrou no processo de adicionar vizinho
  LOG_INFO("NODE DETECTED (NBR)");
  LOG_INFO_("\n");
  //guardar último grupo hexadecimal (nodeID) para verificar se o nó já está registado
  sprintf(nodeip,"%02x%02x::%02x%02x:%02x%02x:%02x%02x:%02x%02x", ((uint8_t *)ipaddr)[0], ((uint8_t *)ipaddr)[1], ((uint8_t *)ipaddr)[8], ((uint8_t *)ipaddr)[9], ((uint8_t *)ipaddr)[10], ((uint8_t *)ipaddr)[11],((uint8_t *)ipaddr)[12], ((uint8_t *)ipaddr)[13], ((uint8_t *)ipaddr)[14], ((uint8_t *)ipaddr)[15]);
  //nó entrou no processo de adicionar vizinho
  LOG_INFO_("\n");
  if ( is_node_removed_motes_nbr(nodeip) == true){
    //em caso de erro, não faz nada
    LOG_INFO(" Invalid Mote");
    LOG_INFO_("\n");
    return NULL;
  }
  //Registo do novo nó fica pendente até aprovação na vitabox
  if(is_node_removed_motes_nbr(nodeip) == false){
    LOG_INFO("Valid Mote");
    LOG_INFO_("\n");
  uip_ds6_nbr_t *nbr = nbr_table_add_lladdr(ds6_neighbors, (linkaddr_t*)lladdr
                                            , reason, data);
  if(nbr) {
    uip_ipaddr_copy(&nbr->ipaddr, ipaddr);
#if UIP_ND6_SEND_RA || !UIP_CONF_ROUTER
    nbr->isrouter = isrouter;
#endif /* UIP_ND6_SEND_RA || !UIP_CONF_ROUTER */
    nbr->state = state;
#if UIP_CONF_IPV6_QUEUE_PKT
    uip_packetqueue_new(&nbr->packethandle);
#endif /* UIP_CONF_IPV6_QUEUE_PKT */
#if UIP_ND6_SEND_NS
    if(nbr->state == NBR_REACHABLE) {
      stimer_set(&nbr->reachable, UIP_ND6_REACHABLE_TIME / 1000);
    } else {
      /* We set the timer in expired state */
      stimer_set(&nbr->reachable, 0);
    }
    stimer_set(&nbr->sendns, 0);
    nbr->nscount = 0;
#endif /* UIP_ND6_SEND_NS */
    LOG_INFO("Adding neighbor with ip addr ");
    LOG_INFO_6ADDR(ipaddr);
    LOG_INFO_(" link addr ");
    LOG_INFO_LLADDR((linkaddr_t*)lladdr);
    LOG_INFO_(" state %u\n", state);
    NETSTACK_ROUTING.neighbor_state_changed(nbr);
    return nbr;
  } else {
    LOG_INFO("Add drop ip addr ");
    LOG_INFO_6ADDR(ipaddr);
    LOG_INFO_(" link addr (%p) ", lladdr);
    LOG_INFO_LLADDR((linkaddr_t*)lladdr);
    LOG_INFO_(" state %u\n", state);
    return NULL;
  }
   }else{
    //em caso de erro, não faz nada
    LOG_INFO(" Invalid Node");
    LOG_INFO_("\n");
    return NULL;
  }
}

/*---------------------------------------------------------------------------*/
int
uip_ds6_nbr_rm(uip_ds6_nbr_t *nbr)
{
  if(nbr != NULL) {
#if UIP_CONF_IPV6_QUEUE_PKT
    uip_packetqueue_free(&nbr->packethandle);
#endif /* UIP_CONF_IPV6_QUEUE_PKT */
    NETSTACK_ROUTING.neighbor_state_changed(nbr);
    return nbr_table_remove(ds6_neighbors, nbr);
  }
  return 0;
}

/*---------------------------------------------------------------------------*/
int
uip_ds6_nbr_update_ll(uip_ds6_nbr_t **nbr_pp, const uip_lladdr_t *new_ll_addr)
{
  uip_ds6_nbr_t nbr_backup;

  if(nbr_pp == NULL || new_ll_addr == NULL) {
    LOG_ERR("%s: invalid argument\n", __func__);
    return -1;
  }

  /* make sure new_ll_addr is not used in some other nbr */
  if(uip_ds6_nbr_ll_lookup(new_ll_addr) != NULL) {
    LOG_ERR("%s: new_ll_addr, ", __func__);
    LOG_ERR_LLADDR((const linkaddr_t *)new_ll_addr);
    LOG_ERR_(", is already used in another nbr\n");
    return -1;
  }

  memcpy(&nbr_backup, *nbr_pp, sizeof(uip_ds6_nbr_t));
  if(uip_ds6_nbr_rm(*nbr_pp) == 0) {
    LOG_ERR("%s: input nbr cannot be removed\n", __func__);
    return -1;
  }

  if((*nbr_pp = uip_ds6_nbr_add(&nbr_backup.ipaddr, new_ll_addr,
                                nbr_backup.isrouter, nbr_backup.state,
                                NBR_TABLE_REASON_IPV6_ND, NULL)) == NULL) {
    LOG_ERR("%s: cannot allocate a new nbr for new_ll_addr\n", __func__);
    return -1;
  }
  memcpy(*nbr_pp, &nbr_backup, sizeof(uip_ds6_nbr_t));

  return 0;
}
/*---------------------------------------------------------------------------*/
const uip_ipaddr_t *
uip_ds6_nbr_get_ipaddr(const uip_ds6_nbr_t *nbr)
{
  return (nbr != NULL) ? &nbr->ipaddr : NULL;
}

/*---------------------------------------------------------------------------*/
const uip_lladdr_t *
uip_ds6_nbr_get_ll(const uip_ds6_nbr_t *nbr)
{
  return (const uip_lladdr_t *)nbr_table_get_lladdr(ds6_neighbors, nbr);
}
/*---------------------------------------------------------------------------*/
int
uip_ds6_nbr_num(void)
{
  uip_ds6_nbr_t *nbr;
  int num;

  num = 0;
  for(nbr = nbr_table_head(ds6_neighbors);
      nbr != NULL;
      nbr = nbr_table_next(ds6_neighbors, nbr)) {
    num++;
  }
  return num;
}
/*---------------------------------------------------------------------------*/
uip_ds6_nbr_t *
uip_ds6_nbr_head(void)
{
  return nbr_table_head(ds6_neighbors);
}
/*---------------------------------------------------------------------------*/
uip_ds6_nbr_t *
uip_ds6_nbr_next(uip_ds6_nbr_t *nbr)
{
  return nbr_table_next(ds6_neighbors, nbr);
}
/*---------------------------------------------------------------------------*/
uip_ds6_nbr_t *
uip_ds6_nbr_lookup(const uip_ipaddr_t *ipaddr)
{
  uip_ds6_nbr_t *nbr = nbr_table_head(ds6_neighbors);
  if(ipaddr != NULL) {
    while(nbr != NULL) {
      if(uip_ipaddr_cmp(&nbr->ipaddr, ipaddr)) {
        return nbr;
      }
      nbr = nbr_table_next(ds6_neighbors, nbr);
    }
  }
  return NULL;
}
/*---------------------------------------------------------------------------*/
uip_ds6_nbr_t *
uip_ds6_nbr_ll_lookup(const uip_lladdr_t *lladdr)
{
  return nbr_table_get_from_lladdr(ds6_neighbors, (linkaddr_t*)lladdr);
}

/*---------------------------------------------------------------------------*/
uip_ipaddr_t *
uip_ds6_nbr_ipaddr_from_lladdr(const uip_lladdr_t *lladdr)
{
  uip_ds6_nbr_t *nbr = uip_ds6_nbr_ll_lookup(lladdr);
  return nbr ? &nbr->ipaddr : NULL;
}

/*---------------------------------------------------------------------------*/
const uip_lladdr_t *
uip_ds6_nbr_lladdr_from_ipaddr(const uip_ipaddr_t *ipaddr)
{
  uip_ds6_nbr_t *nbr = uip_ds6_nbr_lookup(ipaddr);
  return nbr ? uip_ds6_nbr_get_ll(nbr) : NULL;
}
/*---------------------------------------------------------------------------*/
void
uip_ds6_link_callback(int status, int numtx)
{
#if UIP_DS6_LL_NUD
  const linkaddr_t *dest = packetbuf_addr(PACKETBUF_ADDR_RECEIVER);
  if(linkaddr_cmp(dest, &linkaddr_null)) {
    return;
  }

  /* From RFC4861, page 72, last paragraph of section 7.3.3:
   *
   *         "In some cases, link-specific information may indicate that a path to
   *         a neighbor has failed (e.g., the resetting of a virtual circuit). In
   *         such cases, link-specific information may be used to purge Neighbor
   *         Cache entries before the Neighbor Unreachability Detection would do
   *         so. However, link-specific information MUST NOT be used to confirm
   *         the reachability of a neighbor; such information does not provide
   *         end-to-end confirmation between neighboring IP layers."
   *
   * However, we assume that receiving a link layer ack ensures the delivery
   * of the transmitted packed to the IP stack of the neighbour. This is a
   * fair assumption and allows battery powered nodes save some battery by
   * not re-testing the state of a neighbour periodically if it
   * acknowledges link packets. */
  if(status == MAC_TX_OK) {
    uip_ds6_nbr_t *nbr;
    nbr = uip_ds6_nbr_ll_lookup((uip_lladdr_t *)dest);
    if(nbr != NULL && nbr->state != NBR_INCOMPLETE) {
      nbr->state = NBR_REACHABLE;
      stimer_set(&nbr->reachable, UIP_ND6_REACHABLE_TIME / 1000);
      LOG_INFO("received a link layer ACK : ");
      LOG_INFO_LLADDR((uip_lladdr_t *)dest);
      LOG_INFO_(" is reachable.\n");
    }
  }
#endif /* UIP_DS6_LL_NUD */
}
#if UIP_ND6_SEND_NS
/*---------------------------------------------------------------------------*/
/** Periodic processing on neighbors */
void
uip_ds6_neighbor_periodic(void)
{
  uip_ds6_nbr_t *nbr = nbr_table_head(ds6_neighbors);
  while(nbr != NULL) {
    switch(nbr->state) {
    case NBR_REACHABLE:
      if(stimer_expired(&nbr->reachable)) {
#if UIP_CONF_ROUTER
        /* when a neighbor leave its REACHABLE state and is a default router,
           instead of going to STALE state it enters DELAY state in order to
           force a NUD on it. Otherwise, if there is no upward traffic, the
           node never knows if the default router is still reachable. This
           mimics the 6LoWPAN-ND behavior.
         */
        if(uip_ds6_defrt_lookup(&nbr->ipaddr) != NULL) {
          LOG_INFO("REACHABLE: defrt moving to DELAY (");
          LOG_INFO_6ADDR(&nbr->ipaddr);
          LOG_INFO_(")\n");
          nbr->state = NBR_DELAY;
          stimer_set(&nbr->reachable, UIP_ND6_DELAY_FIRST_PROBE_TIME);
          nbr->nscount = 0;
        } else {
          LOG_INFO("REACHABLE: moving to STALE (");
          LOG_INFO_6ADDR(&nbr->ipaddr);
          LOG_INFO_(")\n");
          nbr->state = NBR_STALE;
        }
#else /* UIP_CONF_ROUTER */
        LOG_INFO("REACHABLE: moving to STALE (");
        LOG_INFO_6ADDR(&nbr->ipaddr);
        LOG_INFO_(")\n");
        nbr->state = NBR_STALE;
#endif /* UIP_CONF_ROUTER */
      }
      break;
    case NBR_INCOMPLETE:
      if(nbr->nscount >= UIP_ND6_MAX_MULTICAST_SOLICIT) {
        uip_ds6_nbr_rm(nbr);
      } else if(stimer_expired(&nbr->sendns) && (uip_len == 0)) {
        nbr->nscount++;
        LOG_INFO("NBR_INCOMPLETE: NS %u\n", nbr->nscount);
        uip_nd6_ns_output(NULL, NULL, &nbr->ipaddr);
        stimer_set(&nbr->sendns, uip_ds6_if.retrans_timer / 1000);
      }
      break;
    case NBR_DELAY:
      if(stimer_expired(&nbr->reachable)) {
        nbr->state = NBR_PROBE;
        nbr->nscount = 0;
        LOG_INFO("DELAY: moving to PROBE\n");
        stimer_set(&nbr->sendns, 0);
      }
      break;
    case NBR_PROBE:
      if(nbr->nscount >= UIP_ND6_MAX_UNICAST_SOLICIT) {
        uip_ds6_defrt_t *locdefrt;
        LOG_INFO("PROBE END\n");
        if((locdefrt = uip_ds6_defrt_lookup(&nbr->ipaddr)) != NULL) {
          if (!locdefrt->isinfinite) {
            uip_ds6_defrt_rm(locdefrt);
          }
        }
        uip_ds6_nbr_rm(nbr);
      } else if(stimer_expired(&nbr->sendns) && (uip_len == 0)) {
        nbr->nscount++;
        LOG_INFO("PROBE: NS %u\n", nbr->nscount);
        uip_nd6_ns_output(NULL, &nbr->ipaddr, &nbr->ipaddr);
        stimer_set(&nbr->sendns, uip_ds6_if.retrans_timer / 1000);
      }
      break;
    default:
      break;
    }
    nbr = nbr_table_next(ds6_neighbors, nbr);
  }
}
/*---------------------------------------------------------------------------*/
void
uip_ds6_nbr_refresh_reachable_state(const uip_ipaddr_t *ipaddr)
{
  uip_ds6_nbr_t *nbr;
  nbr = uip_ds6_nbr_lookup(ipaddr);
  if(nbr != NULL) {
    nbr->state = NBR_REACHABLE;
    nbr->nscount = 0;
    stimer_set(&nbr->reachable, UIP_ND6_REACHABLE_TIME / 1000);
  }
}
/*---------------------------------------------------------------------------*/
uip_ds6_nbr_t *
uip_ds6_get_least_lifetime_neighbor(void)
{
  uip_ds6_nbr_t *nbr = nbr_table_head(ds6_neighbors);
  uip_ds6_nbr_t *nbr_expiring = NULL;
  while(nbr != NULL) {
    if(nbr_expiring != NULL) {
      clock_time_t curr = stimer_remaining(&nbr->reachable);
      if(curr < stimer_remaining(&nbr->reachable)) {
        nbr_expiring = nbr;
      }
    } else {
      nbr_expiring = nbr;
    }
    nbr = nbr_table_next(ds6_neighbors, nbr);
  }
  return nbr_expiring;
}
#endif /* UIP_ND6_SEND_NS */
/*---------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------*/
int
ipaddrconv_nbr(const char *addrstr, uip_ip6addr_t *ipaddr)
{
  uint16_t value;
  int tmp, zero;
  unsigned int len;
  char c = 0;  //gcc warning if not initialized

  value = 0;
  zero = -1;
  if(*addrstr == '[') addrstr++;

  for(len = 0; len < sizeof(uip_ip6addr_t) - 1; addrstr++) {
    c = *addrstr;
    if(c == ':' || c == '\0' || c == ']' || c == '/') {
      ipaddr->u8[len] = (value >> 8) & 0xff;
      ipaddr->u8[len + 1] = value & 0xff;
      len += 2;
      value = 0;

      if(c == '\0' || c == ']' || c == '/') {
        break;
      }

      if(*(addrstr + 1) == ':') {
        /* Zero compression */
        if(zero < 0) {
          zero = len;
        }
        addrstr++;
      }
    } else {
      if(c >= '0' && c <= '9') {
        tmp = c - '0';
      } else if(c >= 'a' && c <= 'f') {
        tmp = c - 'a' + 10;
      } else if(c >= 'A' && c <= 'F') {
        tmp = c - 'A' + 10;
      } else {
        LOG_ERR("illegal char: '%c'\n", c);
        return 0;
      }
      value = (value << 4) + (tmp & 0xf);
    }
  }
  if(c != '\0' && c != ']' && c != '/') {
    LOG_ERR("too large address\n");
    return 0;
  }
  if(len < sizeof(uip_ip6addr_t)) {
    if(zero < 0) {
      LOG_ERR("too short address\n");
      return 0;
    }
    memmove(&ipaddr->u8[zero + sizeof(uip_ip6addr_t) - len],
            &ipaddr->u8[zero], len - zero);
    memset(&ipaddr->u8[zero], 0, sizeof(uip_ip6addr_t) - len);
  }

  return 1;
}
/*---------------------------------------------------------------------------*/
static void
udp_rx_callback_nbr(struct simple_udp_connection *c,
         const uip_ipaddr_t *sender_addr,
         uint16_t sender_port,
         const uip_ipaddr_t *receiver_addr,
         uint16_t receiver_port,
         const uint8_t *data,
         uint16_t datalen)
{
  //guardar mensagem vinda da vitabox
  message_nbr = (char *)data;
  LOG_INFO("Received response '%s' from ", message_nbr);
  LOG_INFO_6ADDR(sender_addr);
  LOG_INFO_("\n");
  char moteAddr[30];
  int cont = 0;
  while ( cont < strlen(message_nbr)) {
    moteAddr[cont] = message_nbr[7+cont-1];
    cont++;
  }
  moteAddr[cont] = '\0';
  moteAddr[0] = 'F';
  moteAddr[1] = 'E';
  moteAddr[2] = '8';
  moteAddr[3] = '0';
  //se concatenação de strings de modo a garantir o processo de registo certo
  char flag1[40];
  sprintf(flag1,"remove:%s", moteAddr);
  char flag2[40];
  sprintf(flag2,"add:%s", moteAddr);
  const uip_ipaddr_t *moteIP;
  //se recebe flag1 remove mote da lista de vizinhos e rotas e adiciona à blacklist
  if(strcmp(message_nbr,flag1) == 0){
    leds_off(LEDS_ALL);
    leds_toggle(LEDS_RED);
    ipaddrconv_nbr(moteAddr, (uip_ip6addr_t *)&moteIP);
    uip_ds6_nbr_t *nbr;
    nbr = uip_ds6_nbr_lookup(moteIP);
    uip_ds6_nbr_rm(nbr);
    LOG_INFO("MOTE REMOVED IN NEIGHBOUR TABLE (NBR)");
    LOG_INFO_("\n");
    //adiciona o nodeid ao array local, de modo a bloquear o nó
    for (int i = 0; i < 6; i ++){
      //LOG_INFO("COMPARING NODE IN NBR-- %s -- TO LOCAL DATABASE -- %s\n", addr, removed_motes_nbr[i]);
      if (strcmp(removed_motes_nbr[i],NULL) == 0){
        //se encontrar um campo vazio, adiciona à lista
        strcpy(removed_motes_nbr[i], moteAddr);
        LOG_INFO("MOTE ADDED IN LOCAL DATABASE (NBR) ---- %s\n", removed_motes_nbr[i]);
      } 
    }
    clock_delay(400);
  }
  //se recebe flag2 remove mote da blacklist
  if (strcmp(message_nbr,flag2) == 0){
    leds_off(LEDS_ALL);
    leds_toggle(LEDS_GREEN);
    for (int i = 0; i < 6; i ++){
      //LOG_INFO("COMPARING NODE IN NBR-- %s -- TO LOCAL DATABASE -- %s\n", addr, removed_motes_nbr[i]);
      if (strcmp(removed_motes_nbr[i], moteAddr) == 0){
         strcpy(removed_motes_nbr[i], NULL);
        //se encontrar o nodeid, remove da lista
        LOG_INFO("MOTE REMOVED IN LOCAL DATABASE (NBR) ---- %s\n", removed_motes_nbr[i]);
      } 
    }
    LOG_INFO("MOTE APPROVED IN SERVER MANAGER (NBR)");
    LOG_INFO_("\n");
    clock_delay(400);
  }
}
/*---------------------------------------------------------------------------*/
static void
set_global_address(void)
{
  //definir endereço do servidor (vitabox)
  uip_ip6addr(&server_ipaddr, 0xfd00, 0, 0, 0, 0, 0, 0, 1);
  /* Initialize UDP connection */
  simple_udp_register(&udp_conn_nbr, UDP_CLIENT_PORT, NULL, UDP_SERVER_PORT, udp_rx_callback_nbr);
}

/*---------------------------------------------------------------------------*/
void
uip_ds6_neighbors_init(void)
{
  leds_init();
  leds_toggle(LEDS_BLUE);
  set_global_address();
  link_stats_init();
  nbr_table_register(ds6_neighbors, (nbr_table_callback *)uip_ds6_nbr_rm);
  LOG_INFO("STARTING DS6 NBR\n");
}
