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

#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

struct rte_hash *mac_table = NULL;

#define DEAD_DROP_BOX_SIZE 65536
#define SHM_NAME "/secret"
#define UDP_PORT_SECRET 0xFFFF

#ifndef RTE_IPV4
#define RTE_IPV4(a,b,c,d) ((uint32_t)((a) & 0xff) << 24 | \
                           ((b) & 0xff) << 16 | \
                           ((c) & 0xff) << 8 | \
                           ((d) & 0xff))
#endif

enum SECRET_OP_CODES
{
    DROPOFF = 1,
    PICKUP = 2,
    SUCCESS = 65535,
    FAILURE = 0
};

uint32_t *dead_drop_box;
uint32_t *dead_drop_box_checksum;

struct secret_hdr
{
    uint16_t opCode;     // Operation code
    uint16_t mailboxNum; // Mailbox number
    uint32_t message;    // Message content
};

void *create_shm(void)
{
    int fd = shm_open(SHM_NAME, O_CREAT | O_RDWR, 0666);
    if (fd == -1)
    {
        perror("shm_open");
        return NULL;
    }

    if (ftruncate(fd, sizeof(uint32_t) * DEAD_DROP_BOX_SIZE) == -1)
    {
        perror("ftruncate");
        return NULL;
    }

    void *addr = mmap(0, sizeof(uint32_t) * DEAD_DROP_BOX_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED)
    {
        perror("mmap");
        return NULL;
    }

    close(fd); // fd not needed after mmap
    return addr;
}

// TODO: YOUR CODE HERE (Optional)
static void construct_reply(
    struct rte_mbuf *mbuf,
    struct rte_ether_hdr *eth_hdr,
    struct rte_ipv4_hdr *ipv4_hdr,
    struct rte_udp_hdr *udp_hdr,
    struct secret_hdr *secret_hdr_ptr,
    uint16_t op_code,
    uint32_t message_val
) {
    // Swap MAC, IP address, and UDP ports
    struct rte_ether_addr original_src_mac;
    rte_ether_addr_copy(&eth_hdr->src_addr, &original_src_mac);
    rte_ether_addr_copy(&eth_hdr->dst_addr, &eth_hdr->src_addr);
    rte_ether_addr_copy(&original_src_mac, &eth_hdr->dst_addr);

    uint32_t temp_ip = ipv4_hdr->src_addr;
    ipv4_hdr->src_addr = ipv4_hdr->dst_addr;
    ipv4_hdr->dst_addr = temp_ip;

    uint16_t temp_port = udp_hdr->src_port;
    udp_hdr->src_port = udp_hdr->dst_port;
    udp_hdr->dst_port = temp_port;

    // Set new secret header values 
    secret_hdr_ptr->opCode = rte_cpu_to_be_16(op_code);
    secret_hdr_ptr->message = rte_cpu_to_be_32(message_val);

    // Update checksums
    ipv4_hdr->hdr_checksum = 0;
    ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);

    udp_hdr->dgram_cksum = 0;
    udp_hdr->dgram_cksum = rte_ipv4_udptcp_cksum(ipv4_hdr, udp_hdr);
}

void initialize_mac_address_table()
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

    struct rte_ether_addr *mac1 = malloc(sizeof(struct rte_ether_addr));
    struct rte_ether_addr *mac2 = malloc(sizeof(struct rte_ether_addr));
    rte_ether_unformat_addr("08:00:00:00:01:11", mac1);
    rte_ether_unformat_addr("08:00:00:00:02:22", mac2);

    uint16_t *mac1_data = malloc(sizeof(uint16_t));
    uint16_t *mac2_data = malloc(sizeof(uint16_t));
    *mac1_data = 0; // Port 0
    *mac2_data = 1; // Port 1
    if (rte_hash_add_key_data(mac_table, mac1, mac1_data) < 0 ||
        rte_hash_add_key_data(mac_table, mac2, mac2_data) < 0)
    {
        RTE_LOG(ERR, USER1, "Failed to add MAC addresses to hash table\n");
        free(mac1_data);
        free(mac2_data);
        return;
    }
    RTE_LOG(INFO, USER1, "Initialized MAC table with two entries\n");
}

void initialize_dead_drop_boxes()
{
    dead_drop_box = (uint32_t *)create_shm();
    if (dead_drop_box == NULL)
    {
        rte_exit(EXIT_FAILURE, "Failed to create shared memory\n");
    }
    dead_drop_box_checksum = malloc(sizeof(uint32_t) * DEAD_DROP_BOX_SIZE);
    memset(dead_drop_box_checksum, 0, sizeof(uint32_t) * DEAD_DROP_BOX_SIZE);

    // initialize all entries with 0xdeadbeef
    uint32_t *data = (uint32_t *)dead_drop_box;
    for (size_t i = 0; i < DEAD_DROP_BOX_SIZE; i++)
    {
        data[i] = 0xdeadbeef;
    }
}

void dead_drop_main_loop(void)
{
    RTE_LOG(INFO, USER1, "Starting main loop...\n");
    while (1)
    {
        for (uint16_t port_id = 0; port_id < rte_eth_dev_count_avail(); port_id++)
        {
            struct rte_mbuf *bufs[BURST_SIZE];
            uint16_t nb_rx = rte_eth_rx_burst(port_id, 0, bufs, BURST_SIZE);
            if (nb_rx == 0)
            {
                continue; // No packets received
            }

            for (uint16_t i = 0; i < nb_rx; i++)
            {
                struct rte_mbuf *mbuf = bufs[i];
                struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
                if (eth_hdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))
                {
                    rte_pktmbuf_free(mbuf);
                    return;
                }

                struct rte_ipv4_hdr *ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);

                if (rte_be_to_cpu_32(ipv4_hdr->dst_addr) != RTE_IPV4(10, 0, 0, 254))
                {
                    RTE_LOG(INFO, USER1, "Destination IP is not 10.0.0.254, dropping packet\\n");
                    rte_pktmbuf_free(mbuf);
                    continue;
                }

                if (ipv4_hdr->next_proto_id == IPPROTO_UDP)
                {
                    struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)(ipv4_hdr + 1);

                    // TODO: YOUR CODE HERE
                    if (rte_be_to_cpu_16(udp_hdr->dst_port) == UDP_PORT_SECRET)
                    {
                        
                        struct secret_hdr *secret_payload = (struct secret_hdr *)((char *)udp_hdr + sizeof(struct rte_udp_hdr));
                        uint16_t opCode = rte_be_to_cpu_16(secret_payload->opCode);
                        uint16_t mailboxNum = rte_be_to_cpu_16(secret_payload->mailboxNum);
                        uint32_t message_in = rte_be_to_cpu_32(secret_payload->message);

                        if (opCode == DROPOFF) 
                        {
                            if (dead_drop_box[mailboxNum] == 0xdeadbeef) { 
                                dead_drop_box[mailboxNum] = message_in;
                                dead_drop_box_checksum[mailboxNum] = rte_hash_crc(&message_in, sizeof(message_in), 0);
                                RTE_LOG(INFO, USER1, "DROPOFF SUCCESS for mailbox %u, message=0x%x, checksum=0x%x\\n", mailboxNum, message_in, dead_drop_box_checksum[mailboxNum]);
                                construct_reply(mbuf, eth_hdr, ipv4_hdr, udp_hdr, secret_payload, SUCCESS, 0);
                            } else { // Mailbox already occupied
                                RTE_LOG(INFO, USER1, "DROPOFF FAILURE for mailbox %u: already occupied\\n", mailboxNum);
                                construct_reply(mbuf, eth_hdr, ipv4_hdr, udp_hdr, secret_payload, FAILURE, 0);
                            }
                        } else if (opCode == PICKUP) {
                            if (dead_drop_box[mailboxNum] != 0xdeadbeef) { 
                                uint32_t retrieved_message = dead_drop_box[mailboxNum];
                                uint32_t calculated_checksum = rte_hash_crc(&retrieved_message, sizeof(retrieved_message), 0);

                                if (calculated_checksum == dead_drop_box_checksum[mailboxNum]) {
                                    RTE_LOG(INFO, USER1, "PICKUP SUCCESS for mailbox %u, retrieved message=0x%x\\n", mailboxNum, retrieved_message);
                                    construct_reply(mbuf, eth_hdr, ipv4_hdr, udp_hdr, secret_payload, SUCCESS, retrieved_message);
                                    // Sanitize after successful pickup
                                    dead_drop_box[mailboxNum] = 0xdeadbeef;
                                    dead_drop_box_checksum[mailboxNum] = 0; 
                                } else { // Checksum mismatch
                                    RTE_LOG(INFO, USER1, "PICKUP FAILURE for mailbox %u: checksum mismatch (expected 0x%x, got 0x%x)\\n", mailboxNum, dead_drop_box_checksum[mailboxNum], calculated_checksum);
                                    construct_reply(mbuf, eth_hdr, ipv4_hdr, udp_hdr, secret_payload, FAILURE, 0);
                                }
                            } else { // Mailbox empty
                                RTE_LOG(INFO, USER1, "PICKUP FAILURE for mailbox %u: mailbox empty\\n", mailboxNum);
                                construct_reply(mbuf, eth_hdr, ipv4_hdr, udp_hdr, secret_payload, FAILURE, 0);
                            }
                        } else {
                            RTE_LOG(INFO, USER1, "Invalid operation code: %u\\n", opCode);
                            rte_pktmbuf_free(mbuf);
                            continue;
                        } 
                    } else {
                        RTE_LOG(INFO, USER1, "UDP port %u is not the secret port, dropping packet\\n", rte_be_to_cpu_16(udp_hdr->dst_port));
                        rte_pktmbuf_free(mbuf);
                        continue;
                    }
                    
                }else {
                    RTE_LOG(INFO, USER1, "Next protocol ID is not UDP, dropping packet\\n");
                    rte_pktmbuf_free(mbuf);
                    continue;
                }

                uint16_t *destination_port = NULL;
                RTE_LOG(INFO, USER1, "Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                        eth_hdr->dst_addr.addr_bytes[0], eth_hdr->dst_addr.addr_bytes[1],
                        eth_hdr->dst_addr.addr_bytes[2], eth_hdr->dst_addr.addr_bytes[3],
                        eth_hdr->dst_addr.addr_bytes[4], eth_hdr->dst_addr.addr_bytes[5]);
                if (rte_hash_lookup_data(mac_table, &eth_hdr->dst_addr, (void **)&destination_port) < 0)
                {
                    RTE_LOG(ERR, USER1, "MAC address not found in hash table\n");
                    rte_pktmbuf_free(mbuf);
                }

                if (destination_port != NULL)
                {
                    if (rte_eth_tx_burst(*destination_port, 0, &mbuf, 1) < 1)
                    {
                        RTE_LOG(ERR, USER1, "Failed to send packet on port %u\n", *destination_port);
                        rte_pktmbuf_free(mbuf);
                    }
                    else
                    {
                        RTE_LOG(INFO, USER1, "Packet sent to port %u\n", *destination_port);
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

    initialize_mac_address_table();
    initialize_dead_drop_boxes();

    dead_drop_main_loop();
    return 0;
}
