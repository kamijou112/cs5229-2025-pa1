#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_log.h>
#include <rte_common.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_hash.h>
#include <rte_hash_crc.h>
#include <rte_table.h>
#include <rte_table_hash.h>
#include <rte_lpm.h>

// TODO: YOUR CODE HERE (optional)

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

static struct rte_hash *arp_table = NULL;
static struct rte_lpm *lpm_table = NULL;

static struct rte_ether_addr router_mac;
static uint32_t router_ip[3];

// TODO: YOUR CODE HERE (optional)
static struct rte_ether_addr neighbor_mac[3]; // MACs of directly connected neighbors on each interface

void initialize_router_interfaces()
{
    RTE_LOG(INFO, USER1, "setup L3 router interfaces\n");

    rte_ether_unformat_addr("88:88:88:88:88:88", &router_mac);
    router_ip[0] = RTE_IPV4(10, 0, 0, 254);
    router_ip[1] = RTE_IPV4(192, 168, 1, 254);
    router_ip[2] = RTE_IPV4(172, 16, 0, 254);

    rte_ether_unformat_addr("08:01:00:00:01:11", &neighbor_mac[0]);
    rte_ether_unformat_addr("08:02:00:00:01:11", &neighbor_mac[1]);
    rte_ether_unformat_addr("08:03:00:00:01:11", &neighbor_mac[2]);
}

void initialize_arp_table()
{
    RTE_LOG(INFO, USER1, "init ARP table\n");

    struct rte_hash_parameters arp_params = {
        .name = "arp_table",
        .entries = 1024,
        .key_len = sizeof(uint32_t), // IP address as key
        .hash_func = rte_hash_crc,
        .hash_func_init_val = 0,
        .socket_id = rte_socket_id(),
    };

    arp_table = rte_hash_create(&arp_params);

    // Populate static ARP entries for directly connected hosts
    uint32_t h1_ip = RTE_IPV4(10,0,0,1);
    rte_hash_add_key_data(arp_table, (void *)&h1_ip, (void *)&neighbor_mac[0]);
    RTE_LOG(INFO, USER1, "ARP: Added 10.0.0.1 -> 08:01:00:00:01:11\n");

    uint32_t h2_ip = RTE_IPV4(192,168,1,1);
    rte_hash_add_key_data(arp_table, (void *)&h2_ip, (void *)&neighbor_mac[1]);
    RTE_LOG(INFO, USER1, "ARP: Added 192.168.1.1 -> 08:02:00:00:01:11\n");

    uint32_t h3_ip = RTE_IPV4(172,16,0,1);
    rte_hash_add_key_data(arp_table, (void *)&h3_ip, (void *)&neighbor_mac[2]);
    RTE_LOG(INFO, USER1, "ARP: Added 172.16.0.1 -> 08:03:00:00:01:11\n");

    for (int i = 0; i < 3; ++i) {
        int ret = rte_hash_add_key_data(arp_table, (void *)&router_ip[i], (void *)&router_mac);
        if (ret < 0) {
            RTE_LOG(ERR, USER1, "Failed to add router IP %u.%u.%u.%u to ARP table.\n",
                (router_ip[i] >> 24) & 0xFF, (router_ip[i] >> 16) & 0xFF, (router_ip[i] >> 8) & 0xFF, router_ip[i] & 0xFF);
        } else {
            RTE_LOG(INFO, USER1, "ARP: Added Router IP %u.%u.%u.%u -> %02x:%02x:%02x:%02x:%02x:%02x\n",
                (router_ip[i] >> 24) & 0xFF, (router_ip[i] >> 16) & 0xFF, (router_ip[i] >> 8) & 0xFF, router_ip[i] & 0xFF,
                router_mac.addr_bytes[0], router_mac.addr_bytes[1], router_mac.addr_bytes[2],
                router_mac.addr_bytes[3], router_mac.addr_bytes[4], router_mac.addr_bytes[5]);
        }
    }

}

void initialize_lpm_table()
{
    RTE_LOG(INFO, USER1, "init LPM table\n");

    struct rte_lpm_config lpm_config = {
        .max_rules = 1024,
        .flags = 0,
        .number_tbl8s = 256};

    lpm_table = rte_lpm_create("lpm_table", rte_socket_id(), &lpm_config);
}

void populate_routing_table()
{
    RTE_LOG(INFO, USER1, "insert routes into LPM table\n");
    for (uint32_t i = 0; i < sizeof(router_ip) / sizeof(router_ip[0]); i++)
    {
        uint32_t ip = router_ip[i];
        int ret = rte_lpm_add(lpm_table, ip, 24, i);
        if (ret < 0)
        {
            RTE_LOG(ERR, USER1, "Failed to add route for IP %u.%u.%u.0/24\n",
                    ip >> 24 & 0xFF, (ip >> 16) & 0xFF,
                    (ip >> 8) & 0xFF);
        }
        else
        {
            RTE_LOG(INFO, USER1, "Added route for IP %u.%u.%u.0/24 with next hop via port %u\n",
                    ip >> 24 & 0xFF, (ip >> 16) & 0xFF,
                    (ip >> 8) & 0xFF, i);
        }
    }
}

static inline int is_for_router(uint32_t dst_ip) {
    for (int i = 0; i < 3; i++) {
        if (dst_ip == router_ip[i]) {
            return 1;
        }
    }
    return 0;
}

static void construct_icmp_reply(
    struct rte_mbuf *m,
    struct rte_ether_hdr *eth_hdr,
    struct rte_ipv4_hdr *ipv4_hdr,
    struct rte_icmp_hdr *icmp_hdr
) {
    // 1. Swap MAC addresses
    struct rte_ether_addr temp_eth_addr;
    rte_ether_addr_copy(&eth_hdr->src_addr, &temp_eth_addr); // Store original source
    rte_ether_addr_copy(&router_mac, &eth_hdr->src_addr); // Router's MAC as new source
    rte_ether_addr_copy(&temp_eth_addr, &eth_hdr->dst_addr); // Original source as new destination

    // 2. Swap IP addresses
    uint32_t temp_ip = ipv4_hdr->src_addr;
    ipv4_hdr->src_addr = ipv4_hdr->dst_addr;
    ipv4_hdr->dst_addr = temp_ip;

    // 3. Update ICMP fields
    icmp_hdr->icmp_type = RTE_IP_ICMP_ECHO_REPLY;
    icmp_hdr->icmp_code = 0;

    // 4. Update TTL
    ipv4_hdr->time_to_live = 64; // Standard TTL for replies

    // 5. Recalculate ICMP checksum
    icmp_hdr->icmp_cksum = 0;
    icmp_hdr->icmp_cksum = rte_ipv4_udptcp_cksum(ipv4_hdr, icmp_hdr);

    // 6. Recalculate IP checksum
    ipv4_hdr->hdr_checksum = 0;
    ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);
}

void simple_l3_router_main_loop(void)
{
    RTE_LOG(INFO, USER1, "simple_l3_router main loop\n");

    // TODO: YOUR CODE HERE (optional)

    struct rte_mbuf *bufs[BURST_SIZE];
    while (1)
    {
        for (uint16_t port_id = 0; port_id < rte_eth_dev_count_avail(); port_id++)
        {
            uint16_t nb_rx = rte_eth_rx_burst(port_id, 0, bufs, BURST_SIZE);
            if (nb_rx > 0)
            {
                RTE_LOG(INFO, USER1, "Received %u packets on port %u\n", nb_rx, port_id);
                for (uint16_t i = 0; i < nb_rx; i++)
                {
                    struct rte_mbuf *m = bufs[i];
                    struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

                    // TODO: YOUR CODE HERE
                    // Check for ARP packets first
                    if (eth_hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP))
                    {
                        struct rte_arp_hdr *arp_hdr = (struct rte_arp_hdr *)(eth_hdr + 1);

                        // only care about ARP requests for our router's IP on this specific port
                        if (arp_hdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REQUEST) &&
                            arp_hdr->arp_data.arp_tip == rte_cpu_to_be_32(router_ip[port_id]))
                        {
                            RTE_LOG(INFO, USER1, "ARP Request for router's IP on port %u, sending reply.\n", port_id);

                            // Construct ARP reply
                            // 1. Set opcode to reply
                            arp_hdr->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);

                            // 2. Swap ethernet addresses
                            rte_ether_addr_copy(&eth_hdr->src_addr, &eth_hdr->dst_addr);
                            rte_ether_addr_copy(&router_mac, &eth_hdr->src_addr);

                            // 3. Fill in ARP reply data
                            rte_ether_addr_copy(&arp_hdr->arp_data.arp_sha, &arp_hdr->arp_data.arp_tha);
                            arp_hdr->arp_data.arp_tip = arp_hdr->arp_data.arp_sip;
                            rte_ether_addr_copy(&router_mac, &arp_hdr->arp_data.arp_sha);
                            arp_hdr->arp_data.arp_sip = rte_cpu_to_be_32(router_ip[port_id]);

                            // 4. Send the reply back on the same port
                            if (rte_eth_tx_burst(port_id, 0, &m, 1) < 1) {
                                RTE_LOG(ERR, USER1, "Failed to send ARP reply on port %u.\n", port_id);
                                rte_pktmbuf_free(m);
                            }
                        } else {
                            RTE_LOG(INFO, USER1, " ARP packet not for us, drop it\n");
                            rte_pktmbuf_free(m);
                        }
                        continue; // ARP packet handled, move to the next packet
                    }

                    // process IPv4 packets
                    if (eth_hdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))
                    {
                        RTE_LOG(INFO, USER1, "Non-IPv4 packet received, dropping.\n");
                        rte_pktmbuf_free(m);
                        continue;
                    }

                    struct rte_ipv4_hdr *ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
                    uint32_t dst_ip_be = ipv4_hdr->dst_addr; 
                    uint32_t dst_ip_he = rte_be_to_cpu_32(dst_ip_be); 

                     // Check if packet is for the router itself
                    if (is_for_router(dst_ip_he))
                    {
                        RTE_LOG(INFO, USER1, "Packet for router (Dst IP: %u.%u.%u.%u) received on port %u.\n",
                                (dst_ip_he >> 24) & 0xFF, (dst_ip_he >> 16) & 0xFF, (dst_ip_he >> 8) & 0xFF, dst_ip_he & 0xFF, port_id);

                        if (ipv4_hdr->next_proto_id == IPPROTO_ICMP)
                        {
                            struct rte_icmp_hdr *icmp_hdr = (struct rte_icmp_hdr *)((char *)ipv4_hdr + (ipv4_hdr->ihl * 4));
                            if (icmp_hdr->icmp_type == RTE_IP_ICMP_ECHO_REQUEST && icmp_hdr->icmp_code == 0)
                            {
                                RTE_LOG(INFO, USER1, "ICMP Echo Request for router, sending reply.\n");
                                construct_icmp_reply(m, eth_hdr, ipv4_hdr, icmp_hdr);

                                // Send reply back on the ingress port
                                if (rte_eth_tx_burst(port_id, 0, &m, 1) < 1) {
                                    RTE_LOG(ERR, USER1, "Failed to send ICMP reply on port %u.\n", port_id);
                                    rte_pktmbuf_free(m);
                                } 
                                continue; // Packet handled
                            }
                        }
                        RTE_LOG(INFO, USER1, "Non-ICMP or non-Echo Request packet for router, dropping.\n");
                        rte_pktmbuf_free(m); // Other packets for router are dropped
                        continue;
                    }
                    // forwarding
                    // Decrement TTL and check
                    ipv4_hdr->time_to_live--;
                    if (ipv4_hdr->time_to_live == 0)
                    {
                        RTE_LOG(INFO, USER1, "TTL reached 0, dropping packet.\n");
                        rte_pktmbuf_free(m);
                        continue;
                    }
                    // Recalculate IP checksum
                    ipv4_hdr->hdr_checksum = 0;
                    ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);

                    // LPM lookup for output port
                    uint32_t next_hop_port;
                    int lpm_ret = rte_lpm_lookup(lpm_table, dst_ip_he, &next_hop_port);
                    if (lpm_ret < 0)
                    {
                        RTE_LOG(INFO, USER1, "No route found for destination IP %u.%u.%u.%u, dropping packet.\n",
                                (dst_ip_he >> 24) & 0xFF, (dst_ip_he >> 16) & 0xFF, (dst_ip_he >> 8) & 0xFF, dst_ip_he & 0xFF);
                        rte_pktmbuf_free(m);
                        continue;
                    }
                    // ARP lookup for next hop MAC
                    struct rte_ether_addr *next_hop_mac = NULL;
                    int arp_ret = rte_hash_lookup_data(arp_table, (void *)&dst_ip_he, (void **)&next_hop_mac);

                     // 5. Update Ethernet header for forwarding
                    rte_ether_addr_copy(&router_mac, &eth_hdr->src_addr); 
                    rte_ether_addr_copy(next_hop_mac, &eth_hdr->dst_addr); 

                    // Send packet on output port
                    if (rte_eth_tx_burst(next_hop_port, 0, &m, 1) < 1)
                    {
                        RTE_LOG(ERR, USER1, "Failed to send packet on port %u.\n", next_hop_port);
                        rte_pktmbuf_free(m); 
                    }
                    else
                    {
                        RTE_LOG(INFO, USER1, "Packet forwarded from port %u to port %u (Dst IP: %u.%u.%u.%u).\n",
                                port_id, next_hop_port,
                                (dst_ip_he >> 24) & 0xFF, (dst_ip_he >> 16) & 0xFF, (dst_ip_he >> 8) & 0xFF, dst_ip_he & 0xFF);
                    }

                }
            }
        }
    }
}

int main(int argc, char **argv)
{
    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "EAL init failed\n");

    uint16_t num_ports = rte_eth_dev_count_avail();
    if (num_ports == 0)
        rte_exit(EXIT_FAILURE, "No Ethernet ports available\n");
    RTE_LOG(INFO, USER1, "Number of available ports: %u\n", num_ports);

    struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS,
                                                            MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

    if (!mbuf_pool)
        rte_exit(EXIT_FAILURE, "mbuf_pool creation failed\n");

    for (uint16_t port_id = 0; port_id < num_ports; port_id++)
    {
        struct rte_eth_conf port_conf = {0};
        if (rte_eth_dev_configure(port_id, 1, 1, &port_conf) != 0)
            rte_exit(EXIT_FAILURE, "Failed to configure device\n");

        if (rte_eth_rx_queue_setup(port_id, 0, RX_RING_SIZE, rte_socket_id(), NULL, mbuf_pool) != 0)
            rte_exit(EXIT_FAILURE, "Failed to setup RX queue\n");

        if (rte_eth_tx_queue_setup(port_id, 0, TX_RING_SIZE, rte_socket_id(), NULL) != 0)
            rte_exit(EXIT_FAILURE, "Failed to setup TX queue\n");

        if (rte_eth_dev_start(port_id) < 0)
            rte_exit(EXIT_FAILURE, "Failed to start device\n");
    }

    initialize_router_interfaces();
    initialize_arp_table();
    initialize_lpm_table();
    populate_routing_table();

    simple_l3_router_main_loop();
    return 0;
}
