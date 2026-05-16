// 1. Fundamental Type Definitions
typedef unsigned char   __u8;
typedef unsigned short  __u16;
typedef unsigned int    __u32;
typedef unsigned long long __u64;
typedef short           __s16;
typedef int             __s32;
typedef long long       __s64;
typedef __u16           __be16;
typedef __u32           __be32;

#define ETH_P_IPV6    0x86DD
#define IPPROTO_UDP   17
#define SEC(NAME) __attribute__((section(NAME), used))

#define MY_ETH_HDR 14
#define MY_IP6_HDR 40
#define MY_UDP_HDR 8
#define MY_MIN_PAYLOAD 8
#define MY_MIN_BYTES (MY_ETH_HDR + MY_IP6_HDR + MY_UDP_HDR + MY_MIN_PAYLOAD)
#define MY_MAX_BYTES 1514
#define MY_IPFIX_DPORT 4739
#define MY_ETHPROTO_OFF 12
#define MY_IPPROTO_OFF (MY_ETH_HDR + 6)
#define MY_IPADDR_OFF (MY_ETH_HDR + 8)
#define MY_DPORT_OFF (MY_ETH_HDR + MY_IP6_HDR + 2)
#define MY_CSUM_OFF (MY_ETH_HDR + MY_IP6_HDR + 6)

// Payload checksum will iterate in chunks to
// satisfy BPF static analysis. Max stack buffer
// in BPF is 256 bytes, so that is our chunk size.
#define MY_CHUNK_BYTES 256
// Allow for jumbo PDUs, though in practice it is
// rare for IPFIX to exceed 1500 bytes.
#define MY_MAX_CHUNKS 32

// Core Linux Kernel BPF Header Definitions
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
 
// Helpers
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("classifier")
int fix_ipfix_checksum(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data     = (void *)(long)skb->data;
    __u8 *ptr      = data;

    // Verify raw header sizing window up to my UDP minimum payload
    if ((void *)(ptr + MY_MIN_BYTES) > data_end)
      return TC_ACT_OK;

    // Validate Layer 3 protocol is IPv6
    __u16 eth_proto = (ptr[MY_ETHPROTO_OFF] << 8) | ptr[MY_ETHPROTO_OFF+1];
    if (eth_proto != ETH_P_IPV6)
      return TC_ACT_OK;

    // Validate Layer 4 protocol is UDP
    if (ptr[MY_IPPROTO_OFF] != IPPROTO_UDP)
      return TC_ACT_OK;

    // Validate Destination Port is IPFIX
    __u16 dest_port = (ptr[MY_DPORT_OFF] << 8) | ptr[MY_DPORT_OFF+1];
    if (dest_port != MY_IPFIX_DPORT)
      return TC_ACT_OK;

    // Pull payload into linear memory space
    if (bpf_skb_pull_data(skb, skb->len) < 0)
        return TC_ACT_OK; 
    
    // Re-evaluate boundaries post memory allocation shifts
    data_end = (void *)(long)skb->data_end;
    data     = (void *)(long)skb->data;
    ptr      = data;
    // Repeat verification up to end of min udp payload
    if ((void *)(ptr + MY_MIN_BYTES) > data_end)
      return TC_ACT_OK;

    // Determine the layer-4 payload (UDP header + payload)
    __u32 l4_len = skb->len - (MY_ETH_HDR + MY_IP6_HDR);
    if (l4_len < 8
	|| l4_len > (MY_MAX_BYTES - (MY_ETH_HDR + MY_IP6_HDR)))
      return TC_ACT_OK;

    // Zero out the bad checksum field to prepare for calculation
    __u16 zero_csum = 0;
    if (bpf_skb_store_bytes(skb, MY_CSUM_OFF, &zero_csum, 2, 0) < 0)
      return TC_ACT_OK;

    // Pull IPv6 addresses to the stack for quad-alignment
    struct {
      __be32 src[4];
      __be32 dst[4];
    } ip6_addrs;
    
    if (bpf_skb_load_bytes(skb, MY_IPADDR_OFF, &ip6_addrs, sizeof(ip6_addrs)) < 0)
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
    char chunk[MY_CHUNK_BYTES];
    __u32 bytesLeft = l4_len;
    __u32 cursor = MY_ETH_HDR + MY_IP6_HDR;
    for(int ii = 0; ii < MY_MAX_CHUNKS; ii++) {
      if(bytesLeft > MY_CHUNK_BYTES) {
	if (bpf_skb_load_bytes(skb, cursor, chunk, MY_CHUNK_BYTES) < 0)
	  return TC_ACT_OK;
	csum = bpf_csum_diff(0,0,(__be32 *)chunk, MY_CHUNK_BYTES, csum);
	if (csum < 0)
	  return TC_ACT_OK;
	bytesLeft -= MY_CHUNK_BYTES;
	cursor += MY_CHUNK_BYTES;
      }
      else {
	__builtin_memset(chunk, 0, MY_CHUNK_BYTES);
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

    // Direct memory write back into the packet buffer's checksum field (Offset 60)
    if(bpf_skb_store_bytes(skb, MY_CSUM_OFF, &final_csum, 2, 0) < 0)
      return TC_ACT_OK;

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";

