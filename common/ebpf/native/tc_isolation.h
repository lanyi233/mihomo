// Copyright 2026, sing-box contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// Only L2 framing changes at this boundary. IP addresses, transport ports and
// transport checksums remain untouched in both directions.
#define SB_TC_DELIVERY_MAGIC 0x53425443U
#define SB_TC_RETURN_ETHERNET 0x100U
// Requests the assignment record; never part of the stored return owner.
#define SB_TC_REDIRECT_RECORD 0x200U
#define SB_TC_ACTIVITY_REFRESH_NS 1000000000ULL

// Activity is an idle-cleanup hint, not packet accounting. Coalesce writes
// while preserving immediate publication of identity/generation changes.
INLINE void refresh_tc_activity(__u64 *last_seen, __u64 now) {
    if (now > *last_seen && now - *last_seen >= SB_TC_ACTIVITY_REFRESH_NS)
        *last_seen = now;
}

struct sb_tc_return_value {
    __u64 last_seen_ns;
    __u64 generation;
    __u32 ifindex;
    __u32 flags;
    __u8 source_mac[6];
    __u8 destination_mac[6];
    __u32 reserved;
};
_Static_assert(sizeof(struct sb_tc_return_value) == 40, "sb_tc_return_value ABI size");
_Static_assert(__builtin_offsetof(struct sb_tc_return_value, ifindex) == 16,
    "sb_tc_return_value ifindex ABI offset");

// Unlike assignment metadata, a TCP return route remains necessary after
// accept. Never evict it to admit a new flow; userspace pins live consumers and
// reclaims unreferenced idle entries through bounded maintenance.
MAP(tc_return, struct sb_tc_assign_key, struct sb_tc_return_value, BPF_MAP_TYPE_HASH, 65536U);
// Only locally generated reply fragments use this short-lived cache. It never
// owns a flow and cannot evict a pinned return route. Missing tails fail closed.
MAP(tc_return_frag, struct sb_tc_assign_key, struct sb_tc_return_value, BPF_MAP_TYPE_LRU_HASH, 1024U);

static long (*skb_change_type)(void *ctx, __u32 type) = (void *)BPF_FUNC_skb_change_type;

INLINE void reverse_flow(struct sb_tc_assign_key *reverse, const struct sb_tc_assign_key *flow) {
    *reverse = *flow;
    reverse->source_port = flow->destination_port;
    reverse->destination_port = flow->source_port;
    __builtin_memcpy(reverse->source_addr, flow->destination_addr, 16U);
    __builtin_memcpy(reverse->destination_addr, flow->source_addr, 16U);
}

INLINE bool same_return_owner(const struct sb_tc_return_value *left,
    const struct sb_tc_return_value *right) {
    return left->ifindex == right->ifindex && left->flags == right->flags &&
        source_mac_equal(left->source_mac, right->source_mac) &&
        source_mac_equal(left->destination_mac, right->destination_mac);
}

// Userspace takes a TCP connection's assignment once, when it accepts the
// connection, and then removes it, so only setup packets need to record it.
// Refreshing it from every later packet would cost an LRU lookup per packet
// and recreate the consumed entry; the return route stays refreshed either way.
INLINE __u32 assignment_record(const struct sb_tc_assign_key *flow, __u8 tcp_flag_byte) {
    return flow->protocol != IPPROTO_TCP_VALUE || (tcp_flag_byte & TCP_FLAG_SYN) != 0U
        ? SB_TC_REDIRECT_RECORD : 0U;
}

INLINE int deliver_isolated(struct __sk_buff *skb, const struct sb_tc_control *control, bool ethernet) {
    if (ethernet) {
        if (skb_store_bytes(skb, 0U, control->delivery_mac, 6U, 0U) != 0) return TC_ACT_SHOT;
    } else {
        struct ethernet_header header = {.protocol = skb->protocol};
        __builtin_memcpy(header.destination, control->delivery_mac, 6U);
        if (skb_change_head(skb, sizeof(header), 0U) != 0 ||
            skb_store_bytes(skb, 0U, &header, sizeof(header), 0U) != 0) return TC_ACT_SHOT;
    }
    skb->cb[0] = SB_TC_DELIVERY_MAGIC;
    return redirect((int)control->delivery_ifindex, 0U);
}

NOINLINE int redirect_isolated(struct __sk_buff *skb, const struct sb_tc_control *control,
    const struct sb_tc_assign_key *flow, __u64 cookie, __u32 flags) {
    bool record = (flags & SB_TC_REDIRECT_RECORD) != 0U;
    flags &= ~SB_TC_REDIRECT_RECORD;
    bool ethernet = (flags & SB_TC_RETURN_ETHERNET) != 0U;
    __u8 path = flags & 0xffU;
    __u64 now = ktime_get_ns();
    struct sb_tc_return_value value = {
        .last_seen_ns = now, .generation = now, .ifindex = skb->ifindex, .flags = flags,
    };
    if (ethernet) {
        void *data = (void *)(long)skb->data;
        void *end = (void *)(long)skb->data_end;
        struct ethernet_header *header = data;
        if ((void *)(header + 1) > end) return TC_ACT_SHOT;
        __builtin_memcpy(value.source_mac, header->destination, 6U);
        __builtin_memcpy(value.destination_mac, header->source, 6U);
    }
    struct sb_tc_assign_key reverse;
    reverse_flow(&reverse, flow);
    struct sb_tc_return_value *existing = map_lookup(&tc_return, &reverse);
    if (existing == 0) {
        // Another CPU may publish this flow concurrently. Never overwrite a
        // different publisher (e.g. overlapping addresses on two LANs).
        map_update(&tc_return, &reverse, &value, BPF_NOEXIST);
        existing = map_lookup(&tc_return, &reverse);
    }
    if (existing == 0) {
        record_tc_stat(SB_TC_STAT_RETURN_UPDATE_FAILED);
        return TC_ACT_SHOT;
    }
    if (!same_return_owner(existing, &value)) {
        record_tc_stat(SB_TC_STAT_RETURN_CONFLICT);
        return TC_ACT_SHOT;
    }
    refresh_tc_activity(&existing->last_seen_ns, now);

    if (!record) return deliver_isolated(skb, control, ethernet);

    struct sb_tc_assign_value *previous = map_lookup(&tc_assignment, flow);
    struct sb_tc_assign_value assignment = {
        .socket_cookie = cookie, .last_seen_ns = now, .ifindex = value.ifindex,
        .path = path, .source_mac_valid = ethernet && path == SB_TC_PATH_SHARED,
        .generation = next_assignment_generation(previous),
    };
    __builtin_memcpy(assignment.source_mac, value.destination_mac, 6U);
    if (previous != 0 && !assignment_retired(flow, previous) && previous->socket_cookie == cookie && previous->ifindex == value.ifindex &&
        previous->path == path && previous->source_mac_valid == assignment.source_mac_valid &&
        source_mac_equal(previous->source_mac, assignment.source_mac)) {
        refresh_tc_activity(&previous->last_seen_ns, now);
    } else if (map_update(&tc_assignment, flow, &assignment, BPF_ANY) != 0) {
        record_tc_stat(SB_TC_STAT_ASSIGNMENT_UPDATE_FAILED);
        return TC_ACT_SHOT;
    }
    return deliver_isolated(skb, control, ethernet);
}

INLINE int isolated_delivery(struct __sk_buff *skb, bool legacy, bool udp_only) {
    const struct sb_tc_control *control = load_control();
    if (control == 0 || control->enabled == 0U || skb->cb[0] != SB_TC_DELIVERY_MAGIC) return TC_ACT_SHOT;
    skb->cb[0] = 0U;
    struct sb_tc_assign_key flow;
    __u8 mac[6];
    if (parse_flow_extended(skb, control, SB_TC_FLAG_LOCAL_IPV6 | SB_TC_FLAG_SHARED_IPV6,
            true, false, &flow, mac, 0) != SB_TC_PARSE_FLOW) return TC_ACT_SHOT;
    struct bpf_sock *socket;
    if (!udp_only && flow.protocol == IPPROTO_TCP_VALUE) {
        socket = legacy ? lookup_tcp_socket_legacy(skb, control, &flow) : lookup_tcp_socket(skb, &flow);
    } else {
        // Lookup the private UDP listener at loopback, not at the original
        // remote address. This changes only the lookup key, never the packet.
        // A transparent reply socket can then reuse the listener's port on a
        // different IP without either bind conflicts or lookup ambiguity.
        __builtin_memset(flow.destination_addr, 0, 16U);
        if (flow.family == AF_INET_VALUE) {
            flow.destination_addr[0] = 127U;
            flow.destination_addr[3] = 1U;
        } else {
            flow.destination_addr[15] = 1U;
        }
        socket = lookup_udp_socket(skb, control, &flow);
    }
    if (socket == 0) {
        record_tc_stat(SB_TC_STAT_LISTENER_SOCKET_MISSING);
        return TC_ACT_SHOT;
    }
    long result = sk_assign(skb, socket, 0U);
    sk_release(socket);
    if (result != 0) {
        record_tc_stat(SB_TC_STAT_SK_ASSIGN_FAILED);
        return TC_ACT_SHOT;
    }
    if (skb_change_type(skb, 0U) != 0) return TC_ACT_SHOT; // PACKET_HOST
    skb->mark = control->routing_mark;
    return TC_ACT_OK;
}

SEC("classifier/isolated_delivery")
int sing_ebpf_tc_isolated_delivery(struct __sk_buff *skb) { return isolated_delivery(skb, false, false); }
SEC("classifier/isolated_delivery_legacy")
int sing_ebpf_tc_isolated_delivery_legacy(struct __sk_buff *skb) { return isolated_delivery(skb, true, false); }
SEC("classifier/isolated_delivery_udp")
int sing_ebpf_tc_isolated_delivery_udp(struct __sk_buff *skb) { return isolated_delivery(skb, true, true); }

SEC("classifier/isolated_return")
int sing_ebpf_tc_isolated_return(struct __sk_buff *skb) {
    const struct sb_tc_control *control = load_control();
    if (control == 0 || control->enabled == 0U) return TC_ACT_SHOT;
    struct sb_tc_assign_key flow;
    __u8 mac[6];
    struct sb_tc_fragment fragment = {};
    void *data = (void *)(long)skb->data;
    void *end = (void *)(long)skb->data_end;
    __u16 protocol;
    __u32 offset;
    if (!parse_ethernet(data, end, &protocol, &offset, mac)) return TC_ACT_SHOT;
    if (protocol == ETH_P_IP_VALUE) {
        if (fill_ipv4_key_extended(data, end, offset, control, &flow, &fragment, 0) != SB_TC_PARSE_FLOW) return TC_ACT_SHOT;
    } else if (protocol == ETH_P_IPV6_VALUE) {
        if (fill_ipv6_key_extended(data, end, offset, control, &flow, &fragment, 0) != SB_TC_PARSE_FLOW) return TC_ACT_SHOT;
    } else {
        return TC_ACT_SHOT;
    }
    struct sb_tc_assign_key fragment_key = flow;
    fragment_key.source_port = 0U;
    fragment_key.destination_port = 0U;
    fragment_key.interface_index = fragment.id;
    __u64 now = ktime_get_ns();
    struct sb_tc_return_value *entry;
    if (fragment.state == 2U) {
        entry = map_lookup(&tc_return_frag, &fragment_key);
        if (entry != 0 && now - entry->last_seen_ns > 2000000000ULL) entry = 0;
    } else {
        entry = map_lookup(&tc_return, &flow);
    }
    if (entry == 0) {
        record_tc_stat(SB_TC_STAT_RETURN_LOOKUP_FAILED);
        return TC_ACT_SHOT;
    }
    struct sb_tc_return_value value = *entry;
    if (fragment.state != 2U) refresh_tc_activity(&entry->last_seen_ns, now);
    if (fragment.state == 1U) {
        value.last_seen_ns = now;
        if (map_update(&tc_return_frag, &fragment_key, &value, BPF_ANY) != 0) {
            record_tc_stat(SB_TC_STAT_RETURN_UPDATE_FAILED);
            return TC_ACT_SHOT;
        }
    }
    if ((value.flags & SB_TC_RETURN_ETHERNET) != 0U) {
        if (skb_store_bytes(skb, 0U, value.destination_mac, 6U, 0U) != 0 ||
            skb_store_bytes(skb, 6U, value.source_mac, 6U, 0U) != 0) return TC_ACT_SHOT;
    }
    if (skb_change_type(skb, 0U) != 0) return TC_ACT_SHOT;
    skb->mark = 0U;
    return redirect(value.ifindex, (value.flags & 0xffU) == SB_TC_PATH_DELIVERY ? BPF_F_INGRESS : 0U);
}
