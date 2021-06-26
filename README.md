tc-skeleton
===========

Simple project to demonstrate the loading of eBPF programs via [florianl/go-tc](https://github.com/florianl/go-tc).

```
  $ cd ebpf
  $ make clean
  $ make
  $ cd ..
  $ go run main.go
```

Overview
--------
After the eBPF code is loaded from `ebpf/drop` the eBPF program `dropper` is loaded into the kernel. Modify code according to your real network interface name. Then a [qdisc and filter](https://man7.org/linux/man-pages/man8/tc.8.html) are attached via the [netlink interface](https://man7.org/linux/man-pages/man7/netlink.7.html) of the kernel to this interface. The file descriptor of the eBPF program `dropper` and eBPF map `tc_drop_map` is passed as argument of the filter to the kernel. With attaching the filter to the interface the eBPF program `dropper` will run on every egress packet on the interface.

Privileges
----------
This PoC uses the [`netlink`](https://man7.org/linux/man-pages/man7/netlink.7.html) and [`eBPF`](https://man7.org/linux/man-pages/man2/bpf.2.html) interface of the kernel and therefore it requires special privileges. You can provide this privileges by adjusting the `CAP_NET_ADMIN` capabilities.
