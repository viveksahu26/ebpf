//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define ETH_P_IP    0x0800 

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY); 
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} eventmap SEC(".maps"); 

SEC("xdp")
int xdp_tcp(struct xdp_md *ctx) {
    bpf_printk("Hello !!");

    u16 myport= 4040;

    __u32 key    = 0; 
    __u64 *count = bpf_map_lookup_elem(&eventmap, &key); 
    if (count) { 
        __sync_fetch_and_add(count, 1); 
    }

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
        bpf_printk("Packet has IP Protocol");
        struct iphdr *iph = data + sizeof(ethhdr);

        if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) <= data_end)
        {
            // Check if it's a TCP packet
            if (iph->protocol == IPPROTO_TCP)
            {
                bpf_printk("Packet has TCP Protocol");
                struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);

                if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) <= data_end)
                {
                    // Check destination port
                    if (bpf_ntohs(tcp->dest) == myport)
                    {
                        // u16 value = tcp->dest;
                        bpf_printk("Destination port is: %u\n", tcp->dest);
                        bpf_printk("Source port is: %u\n", tcp->source);
                        return XDP_DROP;
                    }
                }
            }  
        }
    }
    
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
