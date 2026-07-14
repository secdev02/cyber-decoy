// SPDX-License-Identifier: GPL-2.0
//
// decoy.bpf.c
//
// A TC (traffic control) ingress classifier attached to the broker container's
// network interface. It inspects every inbound TCP SYN and emits a connection
// event to a ring buffer so userspace can log every probe, including scans that
// target ports the decoy does not actively serve.
//
// The program does not drop or rewrite packets by default. It is an observation
// layer. Actual proxying to the decoy backends is handled by the userspace
// broker, which listens on the advertised service ports.
//
// The "advertised_ports" map is populated from userspace at startup from the
// service configuration, letting the classifier tag whether an incoming probe
// hit an advertised service or an unsolicited port.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_ACK 0x10

// One record per observed connection attempt.
struct conn_event {
    __u32 src_ip;        // network byte order
    __u32 dst_ip;        // network byte order
    __u16 src_port;      // host byte order
    __u16 dst_port;      // host byte order
    __u8  tcp_flags;     // raw TCP flags byte
    __u8  is_advertised; // 1 if dst_port is a configured service
    __u8  _pad[2];
};

// Ring buffer of connection events consumed by the Go broker.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1 MiB
} events SEC(".maps");

// Set of advertised service ports (SSH/RDP/SMB by default), keyed by
// host-order port number. Populated from userspace.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u16);
    __type(value, __u8);
} advertised_ports SEC(".maps");

SEC("tc")
int decoy_classifier(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    __u32 ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr))
        return TC_ACT_OK;

    struct tcphdr *tcp = (void *)ip + ip_hdr_len;
    if ((void *)(tcp + 1) > data_end)
        return TC_ACT_OK;

    // Read the raw flags byte (offset 13 of the TCP header).
    __u8 flags = ((__u8 *)tcp)[13];

    // Only record fresh connection attempts: SYN set, ACK clear.
    if (!(flags & TCP_FLAG_SYN) || (flags & TCP_FLAG_ACK))
        return TC_ACT_OK;

    __u16 dport = bpf_ntohs(tcp->dest);
    __u8 *found = bpf_map_lookup_elem(&advertised_ports, &dport);

    struct conn_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev)
        return TC_ACT_OK;

    ev->src_ip = ip->saddr;
    ev->dst_ip = ip->daddr;
    ev->src_port = bpf_ntohs(tcp->source);
    ev->dst_port = dport;
    ev->tcp_flags = flags;
    ev->is_advertised = found ? 1 : 0;
    ev->_pad[0] = 0;
    ev->_pad[1] = 0;

    bpf_ringbuf_submit(ev, 0);

    // Let the packet continue to the userspace listener.
    return TC_ACT_OK;
}
