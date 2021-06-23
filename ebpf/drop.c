#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/swab.h>
#include <linux/pkt_cls.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/*
__section("classifier_egress_drop")
int egress_drop(struct __sk_buff *skb) {
	void *data_end = (void *)(unsigned long long)skb->data_end;
	void *data = (void *)(unsigned long long)skb->data;
	struct ethhdr *eth = data;

	// Drop mailformated packet
	if (data + sizeof(struct ethhdr) > data_end)
		return TC_ACT_SHOT;

	// Drop legacy IP traffic
	if (eth->h_proto == ___constant_swab16(ETH_P_IP))
		return TC_ACT_SHOT;

	return TC_ACT_OK;
}
*/

#define bpf_printk(fmt, ...)                            \
({                                                      \
        char ____fmt[] = fmt;                           \
        bpf_trace_printk(____fmt, sizeof(____fmt),      \
                         ##__VA_ARGS__);                \
})

struct bpf_map_def SEC("maps") tc_drop_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 1000,
};

SEC("classifier_ingress_drop")
int ingress_drop(struct __sk_buff *skb) {
	void *data_end = (void *)(unsigned long long)skb->data_end;
	void *data = (void *)(unsigned long long)skb->data;
	struct ethhdr *eth = data;

    int ipsize = sizeof(*eth);
    struct iphdr *ip = data + ipsize;
    ipsize += sizeof(struct iphdr);

    // drop malformed ip packet
    if (data + ipsize > data_end) {
        return TC_ACT_SHOT;
    }

    // drop source of example.com
    if (ip->saddr == ___constant_swab32(1572395042)) {
        bpf_printk("received example.com packet");
        __u32 key = 123;
        __u64 initval = 0, *valp;
        valp = bpf_map_lookup_elem(&tc_drop_map, &key);
        if (!valp) {
            bpf_printk("not found. update elem");
            bpf_map_update_elem(&tc_drop_map, &key, &initval, BPF_ANY);
        } else {
            bpf_printk("found. increment by 1");
            __sync_fetch_and_add(valp, 1);
        }

        return TC_ACT_SHOT;
    }

	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
