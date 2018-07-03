/*
 * Copyright (c) 2016, Inria.
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
 * This file is part of the Contiki operating system.
 */

/**
 * \addtogroup uip
 * @{
 *
 * \file
 *         Source routing support
 *
 * \author Simon Duquennoy <simon.duquennoy@inria.fr>
 */

#include "contiki.h"
#include "net/ipv6/uip-sr.h"
#include "net/ipv6/uiplib.h"
#include "net/routing/routing.h"
#include "lib/list.h"
#include "lib/memb.h"

#include <stdbool.h>
#include <stdio.h>
#include <time.h>
#include "net/ipv6/uiplib.h"
#include "net/ipv6/uip.h"
#include "net/ipv6/uip-ds6.h"

#include "sys/clock.h"
#include "sys/stimer.h"
#include "contiki.h"
#include "random.h"
#include "net/netstack.h"
#include "net/ipv6/simple-udp.h"
#include "net/ipv6/uiplib.h"

/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "IPv6 SR"
#define LOG_LEVEL LOG_LEVEL_INFO

/* Total number of nodes */
static int num_nodes;

// Configuração Sender-Listener --> Vitabox
#define WITH_SERVER_REPLY  0
#define UDP_CLIENT_PORT 8001
#define UDP_SERVER_PORT 10001
//estrutura para conexão UDP
static struct simple_udp_connection udp_conn;
//endereço do servidor (vitabox)
uip_ipaddr_t server_ipaddr;
static char *message;
//array de nós registados na BD local do BR (variável partilhada entre ficheiros) max 10 vizinhos
char approved_nbr[10][6];
//contador para incrementar posição no array
int cont=0;
//estrutura para temporizadores/delays
static struct stimer timer_stimer;

/* Every known node in the network */
LIST(nodelist);
MEMB(nodememb, uip_sr_node_t, UIP_SR_LINK_NUM);
/*---------------------------------------------------------------------------*/
static void
udp_rx_callback(struct simple_udp_connection *c,
         const uip_ipaddr_t *sender_addr,
         uint16_t sender_port,
         const uip_ipaddr_t *receiver_addr,
         uint16_t receiver_port,
         const uint8_t *data,
         uint16_t datalen)
{
  //guardar mensagem vinda da vitabox
  message = (char *)data;
  /* If tagging of traffic class is enabled tc will print number of
     transmission - otherwise it will be 0 */
  LOG_INFO("Received response '%s' from ", message);
  LOG_INFO_6ADDR(sender_addr);
  LOG_INFO_("\n");
}
/*---------------------------------------------------------------------------*/
static void
set_global_address(void)
{
  /* Initialize UDP connection */
  simple_udp_register(&udp_conn, UDP_CLIENT_PORT, NULL, UDP_SERVER_PORT, udp_rx_callback);
  //definir endereço do servidor (vitabox)
  uip_ip6addr(&server_ipaddr, 0xfd00, 0, 0, 0, 0, 0, 0, 1);
}
/*---------------------------------------------------------------------------*/
//método para passar endereço ipv6 para string
void
stringify_IPv6(const uip_ipaddr_t *addr, char *buf)
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
bool is_node_approved_sr(char *addr){
  for (int i = 0; i < 10; i ++){
    //LOG_INFO("COMPARING NODE IN SR -- %s -- TO LOCAL DATABASE -- %s\n", addr, approved_nbr[i]);
    if (strcmp(approved_nbr[i],addr) == 0){
      //se encontrar o nodeid, retorna true
      LOG_INFO("NODE FOUND IN LOCAL DATABASE (SRC) ---- %s\n", approved_nbr[i]);
      return true;
    } 
  }
  //se não encontrar o nodeid, retorna false
  LOG_INFO("NODE NOT FOUND IN LOCAL DATABASE (SRC)\n");
  return false;
}
/*---------------------------------------------------------------------------*/
int
uip_sr_num_nodes(void)
{
  return num_nodes;
}
/*---------------------------------------------------------------------------*/
static int
node_matches_address(void *graph, const uip_sr_node_t *node, const uip_ipaddr_t *addr)
{
  if(node == NULL || addr == NULL || graph != node->graph) {
    return 0;
  } else {
    uip_ipaddr_t node_ipaddr;
    NETSTACK_ROUTING.get_sr_node_ipaddr(&node_ipaddr, node);
    return uip_ipaddr_cmp(&node_ipaddr, addr);
  }
}
/*---------------------------------------------------------------------------*/
uip_sr_node_t *
uip_sr_get_node(void *graph, const uip_ipaddr_t *addr)
{
  uip_sr_node_t *l;
  for(l = list_head(nodelist); l != NULL; l = list_item_next(l)) {
    /* Compare prefix and node identifier */
    if(node_matches_address(graph, l, addr)) {
      return l;
    }
  }
  return NULL;
}
/*---------------------------------------------------------------------------*/
int
uip_sr_is_addr_reachable(void *graph, const uip_ipaddr_t *addr)
{
  int max_depth = UIP_SR_LINK_NUM;
  uip_ipaddr_t root_ipaddr;
  uip_sr_node_t *node;
  uip_sr_node_t *root_node;

  NETSTACK_ROUTING.get_root_ipaddr(&root_ipaddr);
  node = uip_sr_get_node(graph, addr);
  root_node = uip_sr_get_node(graph, &root_ipaddr);

  while(node != NULL && node != root_node && max_depth > 0) {
    node = node->parent;
    max_depth--;
  }
  return node != NULL && node == root_node;
}
/*---------------------------------------------------------------------------*/
void
uip_sr_expire_parent(void *graph, const uip_ipaddr_t *child, const uip_ipaddr_t *parent)
{
  uip_sr_node_t *l = uip_sr_get_node(graph, child);
  /* Check if parent matches */
  if(l != NULL && node_matches_address(graph, l->parent, parent)) {
    l->lifetime = UIP_SR_REMOVAL_DELAY;
  }
}
/*---------------------------------------------------------------------------*/
//no caso de o nó nao ter parent, adiciona um default
uip_sr_node_t *
uip_sr_update_node_parent(void *graph, const uip_ipaddr_t *child, const uip_ipaddr_t *parent, uint32_t lifetime)
{
  uip_sr_node_t *child_node = uip_sr_get_node(graph, child);
  uip_sr_node_t *parent_node = uip_sr_get_node(graph, parent);
  uip_sr_node_t *old_parent_node;
  if(parent != NULL) {
    /* No node for the parent, add one with infinite lifetime */
    if(parent_node == NULL) {
      parent_node = uip_sr_update_node_parent(graph, parent, NULL, UIP_SR_INFINITE_LIFETIME);
      if(parent_node == NULL) {
        LOG_ERR("NS: no space left for root node!\n");
        return NULL;
      }
    }
  }
  /* No node for this child, add one */
  if(child_node == NULL) {
    child_node = memb_alloc(&nodememb);
    /* No space left, abort */
    if(child_node == NULL) {
      LOG_ERR("NS: no space left for child ");
      LOG_ERR_6ADDR(child);
      LOG_ERR_("\n");
      return NULL;
    }
    child_node->parent = NULL;
    list_add(nodelist, child_node);
    num_nodes++;
  }
  /* Initialize node */
  child_node->graph = graph;
  child_node->lifetime = lifetime;
  memcpy(child_node->link_identifier, ((const unsigned char *)child) + 8, 8);
  /* Is the node reachable before the update? */
  if(uip_sr_is_addr_reachable(graph, child)) {
    old_parent_node = child_node->parent;
    /* Update node */
    child_node->parent = parent_node;
    /* Has the node become unreachable? May happen if we create a loop. */
    if(!uip_sr_is_addr_reachable(graph, child)) {
      /* The new parent makes the node unreachable, restore old parent.
       * We will take the update next time, with chances we know more of
       * the topology and the loop is gone. */
      child_node->parent = old_parent_node;
    }
  } else {
    child_node->parent = parent_node;
  }
  LOG_INFO("NS: updating link, child ");
  LOG_INFO_6ADDR(child);
  LOG_INFO_(", parent ");
  LOG_INFO_6ADDR(parent);
  LOG_INFO_(", lifetime %u, num_nodes %u\n", (unsigned)lifetime, num_nodes);
  return child_node;
}
/*---------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------*/
uip_sr_node_t *
uip_sr_update_node(void *graph, const uip_ipaddr_t *child, const uip_ipaddr_t *parent, uint32_t lifetime)
{
  //nó entrou no processo de adicionar rota
  LOG_INFO("NODE DETECTED (SRC)");
  LOG_INFO_("\n");
  //variavel para verificar se o nó a ligar à rede é de confiança ou não
  int flag = 0;
  //string a enviar
  char buf[23];
  //nodeid a comparar
  char nodeid[6];
 //guardar último grupo hexadecimal (nodeID) para verificar se o nó já está registado
  sprintf(nodeid,"%02x%02x", ((uint8_t *)child)[14], ((uint8_t *)child)[15]);
  //nó entrou no processo de adicionar vizinho
  //verificar se o nó já está conectado/aprovado
  if ( is_node_approved_sr(nodeid) == false){
    if(flag == 0 ){
      if(NETSTACK_ROUTING.node_is_reachable()) {
        if(stimer_expired(&timer_stimer)){
          //converter endereço ipv6 para string
          stringify_IPv6(child, buf);
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
          simple_udp_sendto(&udp_conn, &buf, sizeof(buf)+1, &server_ipaddr);
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
      if(strcmp(message,flag1) == 0){
        //atualiza flag
        flag = 1;
        LOG_INFO("NODE APPROVED IN REMOTE DATABASE (SR)");
        LOG_INFO_("\n");
        //adiciona o nodeid ao array local, de modo a registar o nó
        strcpy(approved_nbr[cont], nodeid);
        //incrementa posição no array
        cont++;
      }
      //se recebe flag2 nao regista (nó inválido)
      if (strcmp(message,flag2) == 0){
        //atualiza flag
        flag = 2;
        LOG_INFO("NODE DENIED IN REMOTE DATABASE (SR)");
        LOG_INFO_("\n");
      }
    }
  }
  //se o nó está na BD local do BR, adiciona rota para o vizinho
  if(is_node_approved_sr(nodeid) == true){
  uip_sr_node_t *child_node = uip_sr_get_node(graph, child);
  uip_sr_node_t *parent_node = uip_sr_get_node(graph, parent);
  uip_sr_node_t *old_parent_node;

  if(parent != NULL) {
    /* No node for the parent, add one with infinite lifetime */
    if(parent_node == NULL) {
      parent_node = uip_sr_update_node_parent(graph, parent, NULL, UIP_SR_INFINITE_LIFETIME);
      if(parent_node == NULL) {
        LOG_ERR("NS: no space left for root node!\n");
        return NULL;
      }
    }
  }

  /* No node for this child, add one */
  if(child_node == NULL) {
    child_node = memb_alloc(&nodememb);
    /* No space left, abort */
    if(child_node == NULL) {
      LOG_ERR("NS: no space left for child ");
      LOG_ERR_6ADDR(child);
      LOG_ERR_("\n");
      return NULL;
    }
    child_node->parent = NULL;
    list_add(nodelist, child_node);
    num_nodes++;
  }

  /* Initialize node */
  child_node->graph = graph;
  child_node->lifetime = lifetime;
  memcpy(child_node->link_identifier, ((const unsigned char *)child) + 8, 8);

  /* Is the node reachable before the update? */
  if(uip_sr_is_addr_reachable(graph, child)) {
    old_parent_node = child_node->parent;
    /* Update node */
    child_node->parent = parent_node;
    /* Has the node become unreachable? May happen if we create a loop. */
    if(!uip_sr_is_addr_reachable(graph, child)) {
      /* The new parent makes the node unreachable, restore old parent.
       * We will take the update next time, with chances we know more of
       * the topology and the loop is gone. */
      child_node->parent = old_parent_node;
    }
  } else {
    child_node->parent = parent_node;
  }

  LOG_INFO("NS: updating link, child ");
  LOG_INFO_6ADDR(child);
  LOG_INFO_(", parent ");
  LOG_INFO_6ADDR(parent);
  LOG_INFO_(", lifetime %u, num_nodes %u\n", (unsigned)lifetime, num_nodes);

  return child_node;
   }else{
    //em caso de erro, não faz nada
    LOG_INFO(" Invalid Route");
    LOG_INFO_("\n");
    return NULL;
  }
}
/*---------------------------------------------------------------------------*/
void
uip_sr_init(void)
{
  set_global_address();
  num_nodes = 0;
  memb_init(&nodememb);
  list_init(nodelist);
}
/*---------------------------------------------------------------------------*/
uip_sr_node_t *
uip_sr_node_head(void)
{
  return list_head(nodelist);
}
/*---------------------------------------------------------------------------*/
uip_sr_node_t *
uip_sr_node_next(uip_sr_node_t *item)
{
  return list_item_next(item);
}
/*---------------------------------------------------------------------------*/
void
uip_sr_periodic(unsigned seconds)
{
  uip_sr_node_t *l;
  uip_sr_node_t *next;

  /* First pass, for all expired nodes, deallocate them iff no child points to them */
  for(l = list_head(nodelist); l != NULL; l = next) {
    next = list_item_next(l);
    if(l->lifetime == 0) {
      uip_sr_node_t *l2;
      for(l2 = list_head(nodelist); l2 != NULL; l2 = list_item_next(l2)) {
        if(l2->parent == l) {
          break;
        }
      }
      if(LOG_INFO_ENABLED) {
        uip_ipaddr_t node_addr;
        NETSTACK_ROUTING.get_sr_node_ipaddr(&node_addr, l);
        LOG_INFO("NS: removing expired node ");
        LOG_INFO_6ADDR(&node_addr);
        LOG_INFO_("\n");
      }
      /* No child found, deallocate node */
      list_remove(nodelist, l);
      memb_free(&nodememb, l);
      num_nodes--;
    } else if(l->lifetime != UIP_SR_INFINITE_LIFETIME) {
      l->lifetime = l->lifetime > seconds ? l->lifetime - seconds : 0;
    }
  }
}
/*---------------------------------------------------------------------------*/
void
uip_sr_free_all(void)
{
  uip_sr_node_t *l;
  uip_sr_node_t *next;
  for(l = list_head(nodelist); l != NULL; l = next) {
    next = list_item_next(l);
    list_remove(nodelist, l);
    memb_free(&nodememb, l);
    num_nodes--;
  }
}
/*---------------------------------------------------------------------------*/
int
uip_sr_link_snprint(char *buf, int buflen, uip_sr_node_t *link)
{
  int index = 0;
  uip_ipaddr_t child_ipaddr;
  uip_ipaddr_t parent_ipaddr;

  NETSTACK_ROUTING.get_sr_node_ipaddr(&child_ipaddr, link);
  NETSTACK_ROUTING.get_sr_node_ipaddr(&parent_ipaddr, link->parent);

  if(LOG_WITH_COMPACT_ADDR) {
    index += log_6addr_compact_snprint(buf+index, buflen-index, &child_ipaddr);
  } else {
    index += uiplib_ipaddr_snprint(buf+index, buflen-index, &child_ipaddr);
  }
  if(index >= buflen) {
    return index;
  }

  if(link->parent == NULL) {
    index += snprintf(buf+index, buflen-index, "  (DODAG root)");
    if(index >= buflen) {
      return index;
    }
  } else {
    index += snprintf(buf+index, buflen-index, "  to ");
    if(index >= buflen) {
      return index;
    }
    if(LOG_WITH_COMPACT_ADDR) {
      index += log_6addr_compact_snprint(buf+index, buflen-index, &parent_ipaddr);
    } else {
      index += uiplib_ipaddr_snprint(buf+index, buflen-index, &parent_ipaddr);
    }
    if(index >= buflen) {
      return index;
    }
  }
  if(link->lifetime != UIP_SR_INFINITE_LIFETIME) {
    index += snprintf(buf+index, buflen-index,
              " (lifetime: %lu seconds)", (unsigned long)link->lifetime);
    if(index >= buflen) {
      return index;
    }
  } else {
    index += snprintf(buf+index, buflen-index, " (lifetime: infinite)");
    if(index >= buflen) {
      return index;
    }
  }
  return index;
}
/** @} */
