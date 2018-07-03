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
char approved_nbr[10][6];
//contador para incrementar posição no array
int cont_nbr=0;
//estrutura para temporizadores/delays
static struct stimer timer_stimer;

NBR_TABLE_GLOBAL(uip_ds6_nbr_t, ds6_neighbors);

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
  /* If tagging of traffic class is enabled tc will print number of
     transmission - otherwise it will be 0 */
  LOG_INFO("Received response '%s' from ", message_nbr);
  LOG_INFO_6ADDR(sender_addr);
  LOG_INFO_("\n");
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
//método para passar endereço ipv6 para string
void
stringify_IPv6_nbr(const uip_ipaddr_t *addr, char *buf)
{
  char aux1[2] ;
  char aux2[2] ;
  char aux3[2] ;
	strcpy(buf, "");
  strcpy(aux2, "::");
  strcpy(aux3, ":");
  int k;
  for (k = 0; k < 16; k++) {
    if(k==2){
      k= k + 6;
      strcat(buf, aux2);
    }else{
      if(k%2 == 0 && k != 0){
        strcat(buf, aux3);
      }
    }
    if(k%2 == 0){
      sprintf(aux1, "%x",addr->u8[k]);
    }else{
      sprintf(aux1, "%02x",addr->u8[k]);
    }
    strcat(buf, aux1);
  }
}
/*---------------------------------------------------------------------------*/
//método para verificar se nó já foi aprovado no registo de vizinhos
bool is_node_approved_nbr(char *addr){
  for (int i = 0; i < 10; i ++){
    //LOG_INFO("COMPARING NODE IN NBR-- %s -- TO LOCAL DATABASE -- %s\n", addr, approved_nbr[i]);
    if (strcmp(approved_nbr[i],addr) == 0){
      //se encontrar o nodeid, retorna true
      LOG_INFO("NODE FOUND IN LOCAL DATABASE (NBR) ---- %s\n", approved_nbr[i]);
      return true;
    } 
  }
  //se não encontrar o nodeid, retorna false
  LOG_INFO("NODE NOT FOUND IN LOCAL DATABASE (NBR)\n");
  return false;
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
  //variavel para verificar se o nó a ligar à rede é de confiança ou não
  int flag = 0;
  //string a enviar
  char buf[23];
  //nodeid a comparar
  char nodeid[6];
  //nodeip a enviar
  char nodeip[40];
  //guardar último grupo hexadecimal (nodeID) para verificar se o nó já está registado
  sprintf(nodeid,"%02x%02x", ((uint8_t *)ipaddr)[14], ((uint8_t *)ipaddr)[15]);
  sprintf(nodeip,"%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x", ((uint8_t *)ipaddr)[0], ((uint8_t *)ipaddr)[1], ((uint8_t *)ipaddr)[2], ((uint8_t *)ipaddr)[3], ((uint8_t *)ipaddr)[4], ((uint8_t *)ipaddr)[5], ((uint8_t *)ipaddr)[6], ((uint8_t *)ipaddr)[7], ((uint8_t *)ipaddr)[8], ((uint8_t *)ipaddr)[9], ((uint8_t *)ipaddr)[10], ((uint8_t *)ipaddr)[11],((uint8_t *)ipaddr)[12], ((uint8_t *)ipaddr)[13], ((uint8_t *)ipaddr)[14], ((uint8_t *)ipaddr)[15]);
  //nó entrou no processo de adicionar vizinho
  //LOG_INFO("LAST GROUP HEXADECIMAL - %s", nodeid);
  LOG_INFO_("\n");
  if ( is_node_approved_nbr(nodeid) == false){
    if(flag == 0 ){
      if(NETSTACK_ROUTING.node_is_reachable()) {
        if(stimer_expired(&timer_stimer)){
          //converter endereço ipv6 para string
          stringify_IPv6_nbr(ipaddr, buf);
          /* Send to DAG root */
          LOG_INFO("Sending address %s to ", buf);
          LOG_INFO_6ADDR(&server_ipaddr);
          LOG_INFO_("\n");
          /* Set the number of transmissions to use for this packet -
          this can be used to create more reliable transmissions or
          less reliable than the default. Works end-to-end if
          UIP_CONF_TAG_TC_WITH_VARIABLE_RETRANSMISSIONS is set to 1.
          */
          uipbuf_set_attr(UIPBUF_ATTR_MAX_MAC_TRANSMISSIONS, 2);
          //envia endereço do nó que quer registar na DAG para a vitabox
          simple_udp_sendto(&udp_conn_nbr, &buf, sizeof(buf)+1, &server_ipaddr);
          stimer_set(&timer_stimer, 10);
        }
      } else {
        //não chega ao nó
        LOG_INFO("---- Not reachable yet");
        LOG_INFO_("\n");
      }
      //se concatenação de strings de modo a garantir o processo de registo certo
      char flag1[40];
      sprintf(flag1,"flag1:%s", nodeid);
      char flag2[40];
      sprintf(flag2,"flag2:%s", nodeid);
       //se recebe flag1 regista (nó válido)
      if(strcmp(message_nbr,flag1) == 0){
        leds_off(LEDS_ALL);
        leds_toggle(LEDS_GREEN);
        //atualiza flag
        flag = 1;
        LOG_INFO("NODE APPROVED IN REMOTE DATABASE (NBR)");
        LOG_INFO_("\n");
        //adiciona o nodeid ao array local, de modo a registar o nó
        strcpy(approved_nbr[cont_nbr], nodeid);
        //incrementa posição no array
        cont_nbr++;
        clock_delay(400);
      }
      //se recebe flag2 nao regista (nó inválido)
      if (strcmp(message_nbr,flag2) == 0){
        leds_off(LEDS_ALL);
        leds_toggle(LEDS_RED);
        //atualiza flag
        flag = 2;
        LOG_INFO("NODE DENIED IN REMOTE DATABASE (NBR)");
        LOG_INFO_("\n");
        clock_delay(400);
      }
    }
  }
  //Registo do novo nó fica pendente até aprovação na vitabox
  if(is_node_approved_nbr(nodeid) == true){
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
/** @} */
