#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "tcppacket.h"

SEC("xdp")
int xdp_tcp(struct xdp_md *ctx) {
        bpf_printk("Hello !!");

        // starting address of network packet
        void *data = (void *)(long)ctx->data;

        // ending address of network packet
        void *data_end = (void *)(long)ctx->data_end;

        // Treats the packet data as an Ethernet header
        struct ethhdr *eth = data;

        // check if the Ethernet header exceeds the packet end pointer
        //  If so, it returns 0, indicating an invalid packet.
        if (data + sizeof(struct ethhdr) > data_end)
            return 0;

        // Check if it's an IP packet
        if (bpf_ntohs(eth->h_proto) == ETH_P_IP)
        {
            bpf_printk("Yes, it's a IP Protocol");
            struct iphdr *iph = data + sizeof(struct ethhdr);

            if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) <= data_end)
            {
                // Check if it's a TCP packet
                if (iph->protocol == IPPROTO_TCP)
                {
                    bpf_printk("TCP TCP !!");
                    struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);

                    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) <= data_end)
                    {
                          // Check destination port
                        if (bpf_ntohs(tcp->dest) == 4040) 
                        {
                            // u16 value = tcp->dest;
                            bpf_printk("Hello port is: %u\n", tcp->dest);
                            return XDP_DROP;
                        }
                    }
                }  
            }
        }
    }
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
