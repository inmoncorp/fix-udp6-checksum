// Core Linux Kernel Header Definitions
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/in.h>

// BPF Helpers
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MIN_PAYLOAD 8
#define IPFIX_PORT 4739
#define MAX_BYTES ETH_FRAME_LEN
#define ETHHDR_BYTES sizeof(struct ethhdr)
#define IPV6HDR_BYTES sizeof(struct ipv6hdr)
#define UDPHDR_BYTES sizeof(struct udphdr)
#define MIN_BYTES (ETHHDR_BYTES + IPV6HDR_BYTES + UDPHDR_BYTES + MIN_PAYLOAD)
#define IP6ADDR_OFF (ETHHDR_BYTES + offsetof(struct ipv6hdr, saddr))
#define CSUM_OFF (ETHHDR_BYTES + IPV6HDR_BYTES + offsetof(struct udphdr, check))

struct vlan_hdr {
  __u16 tci;
  __u16 next_proto;
} __attribute((packed));

// Payload checksum will iterate in chunks to
// satisfy BPF static analysis. Max stack buffer
// in BPF is 256 bytes, so that is our chunk size.
#define CHUNK_BYTES 256
#define MAX_CHUNKS 8

// When LOGGING is > 0, output can be seen with:
//   sudo cat /sys/kernel/tracing/trace_pipe
// The larger the setting, the more output will appear, so
// be careful because something like LOGGING 4 may
// log a message for every received IP6 packet, which
// could impact the performance of the system and cause
// the kernel to drop packets.
#define LOGGING 0

SEC("tc/ingress")
int fix_ipfix_checksum(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data     = (void *)(long)skb->data;
    __u8 *ptr      = data;

    // Parse Ethernet Header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    __u32 proto = bpf_ntohs(eth->h_proto);
    struct vlan_hdr *vl = NULL;
    if(proto == ETH_P_8021Q) {
#if LOGGING > 4
      bpf_printk("fix_checksum: VLAN header");
#endif
      vl = (void *)(eth + 1);
      if ((void *)(vl + 1) > data_end)
        return TC_ACT_OK;
      proto = bpf_ntohs(vl->next_proto);
    }
    if (proto != ETH_P_IPV6)
        return TC_ACT_OK;

#if LOGGING > 3
    bpf_printk("fix_checksum: IP6 header");
#endif

    // Parse IPv6 Header
    // Header extensions not supported
    struct ipv6hdr *ipv6 = vl ? (void *)(vl + 1) : (void *)(eth + 1);
    if ((void *)(ipv6 + 1) > data_end)
        return TC_ACT_OK;
    __u8 nexthdr = ipv6->nexthdr;
#if LOGGING > 3
    bpf_printk("fix_checksum: IP6 next_header=%u", nexthdr);
#endif
    if (nexthdr != IPPROTO_UDP) {
        return TC_ACT_OK;
    }

#if LOGGING > 2
    bpf_printk("fix_checksum: UDP header");
#endif

    // Parse UDP Header
    struct udphdr *udp = (void *)(ipv6 + 1);
    if ((void *)(udp + 1) > data_end) {
        return TC_ACT_OK;
    }
    __u32 dport = bpf_ntohs(udp->dest);
    if(dport != IPFIX_PORT) {
        return TC_ACT_OK;
    }
#if LOGGING > 1
    bpf_printk("fix_checksum: IPFIX packet");
#endif
    // Pull payload into linear memory space
    if (bpf_skb_pull_data(skb, skb->len) < 0)
        return TC_ACT_OK;

    // Re-evaluate boundaries post memory allocation shifts
    data_end = (void *)(long)skb->data_end;
    data     = (void *)(long)skb->data;
    ptr      = data;
    // Repeat verification up to end of min udp payload
    if ((void *)(ptr + MIN_BYTES) > data_end)
        return TC_ACT_OK;

    // Determine the layer-4 payload (UDP header + payload)
    __u32 l4_len = skb->len - ETHHDR_BYTES - IPV6HDR_BYTES;
    if (l4_len < 8
	|| l4_len > (MAX_BYTES - ETHHDR_BYTES - IPV6HDR_BYTES))
        return TC_ACT_OK;

    // Zero out the bad checksum field to prepare for calculation
    __u16 zero_csum = 0;
    if (bpf_skb_store_bytes(skb, CSUM_OFF, &zero_csum, 2, 0) < 0)
        return TC_ACT_OK;

    // Pull IPv6 addresses to the stack for quad-alignment
    struct {
        __be32 src[4];
        __be32 dst[4];
    } ip6_addrs;

    if (bpf_skb_load_bytes(skb, IP6ADDR_OFF, &ip6_addrs, sizeof(ip6_addrs)) < 0)
        return TC_ACT_OK;

    // Kick off checksum on these
    __s64 csum = bpf_csum_diff(0, 0, (__be32 *)&ip6_addrs, sizeof(ip6_addrs), 0);
    if (csum < 0)
        return TC_ACT_OK;

    // Construct pseudo-header with length/protocol
    __u32 pseudo_meta[2];
    pseudo_meta[0] = bpf_htonl(l4_len);
    pseudo_meta[1] = bpf_htonl(17); // Protocol UDP padded to 4 bytes

    // Accumulate into checksum
    csum = bpf_csum_diff(0, 0, pseudo_meta, sizeof(pseudo_meta), csum);
    if (csum < 0)
        return TC_ACT_OK;

    // Accumulate payload checksum. Iterate in chunks to satisfy
    // static analysis
    char chunk[CHUNK_BYTES];
    __u32 bytesLeft = l4_len;
    __u32 cursor = ETHHDR_BYTES + IPV6HDR_BYTES;
    for(int ii = 0; ii < MAX_CHUNKS; ii++) {
        if(bytesLeft > CHUNK_BYTES) {
	    if (bpf_skb_load_bytes(skb, cursor, chunk, CHUNK_BYTES) < 0)
	        return TC_ACT_OK;
	    csum = bpf_csum_diff(0,0,(__be32 *)chunk, CHUNK_BYTES, csum);
	    if (csum < 0)
	        return TC_ACT_OK;
	    bytesLeft -= CHUNK_BYTES;
	    cursor += CHUNK_BYTES;
        }
        else {
	    __builtin_memset(chunk, 0, CHUNK_BYTES);
	    if (bpf_skb_load_bytes(skb, cursor, chunk, bytesLeft) < 0)
	        return TC_ACT_OK;
	    __u32 quadsLeft = ((bytesLeft + 3) >> 2);
	    csum = bpf_csum_diff(0,0,(__be32 *)chunk, (quadsLeft << 2), csum);
	    if (csum < 0)
	        return TC_ACT_OK;
	    break;
        }
    }

    // Fold the 32-bit checksum value down into a valid 16-bit 1's complement field
    __u32 folded_csum = (csum & 0xFFFF) + (csum >> 16);
    folded_csum = (folded_csum & 0xFFFF) + (folded_csum >> 16);

    // Explicit bitwise NOT inversion to compute the true standard Internet Checksum
    __u16 final_csum = (__u16)(~folded_csum);

    // If the final computed checksum evaluates to 0x0000, it must be sent as 0xFFFF in IPv6 UDP
    if (final_csum == 0)
        final_csum = 0xFFFF;
#if LOGGING > 0
    bpf_printk("fix_checksum: overwriting IP6 checksum");
#endif
    // Direct memory write back into the packet buffer's checksum field (Offset 60)
    if(bpf_skb_store_bytes(skb, CSUM_OFF, &final_csum, 2, 0) < 0)
        return TC_ACT_OK;

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";

