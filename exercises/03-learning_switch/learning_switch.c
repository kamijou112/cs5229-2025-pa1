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
#include <rte_table.h>
#include <rte_hash_crc.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

static struct rte_hash *mac_table = NULL;

void initialize_mac_table(void)
{
    if (mac_table == NULL)
    {
        struct rte_hash_parameters hash_params = {
            .name = "mac_table",
            .entries = 1024,
            .key_len = sizeof(struct rte_ether_addr),
            .hash_func = rte_hash_crc,
            .hash_func_init_val = 0,
            .socket_id = rte_socket_id(),
        };
        mac_table = rte_hash_create(&hash_params);
    }
}

// TODO: YOUR CODE HERE (Optional)
static inline int is_broadcast_mac(const struct rte_ether_addr *mac_addr) {
    return (mac_addr->addr_bytes[0] == 0xff &&
            mac_addr->addr_bytes[1] == 0xff &&
            mac_addr->addr_bytes[2] == 0xff &&
            mac_addr->addr_bytes[3] == 0xff &&
            mac_addr->addr_bytes[4] == 0xff &&
            mac_addr->addr_bytes[5] == 0xff);
}

void learning_switch_main_loop(void)
{
    RTE_LOG(INFO, USER1, "Starting learning switch main loop\n");

    while (1)
    {
        for (uint16_t port_id = 0; port_id < rte_eth_dev_count_avail(); port_id++)
        {
            struct rte_mbuf *bufs[BURST_SIZE];
            const uint16_t nb_rx = rte_eth_rx_burst(port_id, 0, bufs, BURST_SIZE);

            if (nb_rx == 0)
                continue;

            for (uint16_t i = 0; i < nb_rx; i++)
            {
                struct rte_mbuf *m = bufs[i];
                struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

                // TODO: YOUR CODE HERE
                // 1. MAC Learning: Learn source MAC address and ingress port
                int ret = rte_hash_lookup_data(mac_table, &eth_hdr->src_addr, NULL); // Check if source MAC exists
                if (ret < 0) { // MAC not found, add it
                    uint16_t *out_port = malloc(sizeof(uint16_t));
                    if (out_port == NULL) {
                        RTE_LOG(ERR, USER1, "Failed to allocate memory for port data, dropping packet.\\n");
                        rte_pktmbuf_free(m);
                        continue;
                    }
                    *out_port = port_id; // Store the ingress port
                    rte_hash_add_key_data(mac_table, &eth_hdr->src_addr, (void *)out_port);
                    RTE_LOG(INFO, USER1, "Learned MAC: %02x:%02x:%02x:%02x:%02x:%02x on port %u\\n",
                            eth_hdr->src_addr.addr_bytes[0], eth_hdr->src_addr.addr_bytes[1],
                            eth_hdr->src_addr.addr_bytes[2], eth_hdr->src_addr.addr_bytes[3],
                            eth_hdr->src_addr.addr_bytes[4], eth_hdr->src_addr.addr_bytes[5], port_id);
                } else {
                    // MAC already exists, ensure the port is correct (e.g., if host moved, update it)
                    uint16_t *existing_port = NULL;
                    rte_hash_lookup_data(mac_table, &eth_hdr->src_addr, (void **)&existing_port);
                    if (existing_port != NULL && *existing_port != port_id) {
                         RTE_LOG(INFO, USER1, "MAC %02x:%02x:%02x:%02x:%02x:%02x moved from port %u to %u\\n",
                            eth_hdr->src_addr.addr_bytes[0], eth_hdr->src_addr.addr_bytes[1],
                            eth_hdr->src_addr.addr_bytes[2], eth_hdr->src_addr.addr_bytes[3],
                            eth_hdr->src_addr.addr_bytes[4], eth_hdr->src_addr.addr_bytes[5], *existing_port, port_id);
                        *existing_port = port_id; // Update port if host moved
                    }
                }

                // 2. Forwarding Decision based on Destination MAC
                if (is_broadcast_mac(&eth_hdr->dst_addr)) {
                    // Flood broadcast packets to all ports except ingress
                    RTE_LOG(INFO, USER1, "Broadcast packet received on port %u, flooding.\\n", port_id);
                    for (uint16_t p = 0; p < num_eth_ports; p++) {
                        if (p == port_id) continue; // Don't send back to ingress port
                        // Duplicate mbuf for each output port
                        struct rte_mbuf *m_copy = rte_pktmbuf_clone(m, m->pool);
                        if (m_copy == NULL) {
                            RTE_LOG(ERR, USER1, "Failed to clone mbuf for flooding, dropping broadcast packet to port %u.\\n", p);
                            continue; // Try next port
                        }
                        if (rte_eth_tx_burst(p, 0, &m_copy, 1) < 1) {
                            RTE_LOG(ERR, USER1, "Failed to send broadcast packet on port %u.\\n", p);
                            rte_pktmbuf_free(m_copy); // Free if transmission failed
                        }
                    }
                    rte_pktmbuf_free(m); // Free original mbuf after cloning for all ports
                } else {
                    // Unicast or unknown destination
                    uint16_t *out_port = NULL;
                    ret = rte_hash_lookup_data(mac_table, &eth_hdr->dst_addr, (void **)&out_port);

                    if (ret < 0 || out_port == NULL) {
                        // Destination MAC unknown, drop packet
                        RTE_LOG(INFO, USER1, "Unknown destination MAC: %02x:%02x:%02x:%02x:%02x:%02x, dropping packet.\\n",
                                eth_hdr->dst_addr.addr_bytes[0], eth_hdr->dst_addr.addr_bytes[1],
                                eth_hdr->dst_addr.addr_bytes[2], eth_hdr->dst_addr.addr_bytes[3],
                                eth_hdr->dst_addr.addr_bytes[4], eth_hdr->dst_addr.addr_bytes[5]);
                        rte_pktmbuf_free(m);
                    } else {
                        // Destination MAC known, forward to specific port
                        if (*out_port == port_id) {
                            RTE_LOG(INFO, USER1, "Packet to known MAC %02x:%02x:%02x:%02x:%02x:%02x for same ingress port %u, dropping.\\n",
                                eth_hdr->dst_addr.addr_bytes[0], eth_hdr->dst_addr.addr_bytes[1],
                                eth_hdr->dst_addr.addr_bytes[2], eth_hdr->dst_addr.addr_bytes[3],
                                eth_hdr->dst_addr.addr_bytes[4], eth_hdr->dst_addr.addr_bytes[5], port_id);
                            rte_pktmbuf_free(m); // Drop if destination is same as ingress (no need to send back)
                        } else {
                            RTE_LOG(INFO, USER1, "Forwarding packet from port %u to port %u (Dest MAC: %02x:%02x:%02x:%02x:%02x:%02x).\\n",
                                    port_id, *out_port,
                                    eth_hdr->dst_addr.addr_bytes[0], eth_hdr->dst_addr.addr_bytes[1],
                                    eth_hdr->dst_addr.addr_bytes[2], eth_hdr->dst_addr.addr_bytes[3],
                                    eth_hdr->dst_addr.addr_bytes[4], eth_hdr->dst_addr.addr_bytes[5]);
                            if (rte_eth_tx_burst(*out_port, 0, &m, 1) < 1) {
                                RTE_LOG(ERR, USER1, "Failed to send packet to port %u.\\n", *out_port);
                                rte_pktmbuf_free(m); // Free if transmission failed
                            } else {
                                // Packet successfully sent, DPDK frees mbuf.
                            }
                        }
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

    initialize_mac_table();
    learning_switch_main_loop();
    return 0;
}
