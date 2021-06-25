package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"

	"github.com/jsimonetti/rtnetlink"

	"github.com/florianl/go-tc"
	helper "github.com/florianl/go-tc/core"

	"golang.org/x/sys/unix"
)

// setupDummyInterface installs a temporary dummy interface
func setupDummyInterface(iface string) (*rtnetlink.Conn, error) {
	con, err := rtnetlink.Dial(nil)
	if err != nil {
		return &rtnetlink.Conn{}, err
	}
	if err := con.Link.New(&rtnetlink.LinkMessage{
		Family: unix.AF_UNSPEC,
		Type:   unix.ARPHRD_NETROM,
		Index:  0,
		Flags:  unix.IFF_UP,
		Change: unix.IFF_UP,
		Attributes: &rtnetlink.LinkAttributes{
			Name: iface,
			Info: &rtnetlink.LinkInfo{Kind: "dummy"},
		},
	}); err != nil {
		return con, err
	}
	return con, err
}

func uint32Ptr(v uint32) *uint32 {
	return &v
}

func stringPtr(v string) *string {
	return &v
}

type BPFObjects struct {
	TcDropper *ebpf.Program `ebpf:"dropper"`
	DropMap   *ebpf.Map     `ebpf:"tc_drop_map"`
}

func main() {
	// Load eBPF from an elf file
	spec, err := ebpf.LoadCollectionSpec("ebpf/drop")
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not load collection from file: %v\n", err)
		os.Exit(1)
	}

	// Load programs and maps
	obj := BPFObjects{}
	if err := spec.LoadAndAssign(&obj, nil); err != nil {
		fmt.Fprintf(os.Stderr, "could not load programs and maps: %v\n", err)
		os.Exit(1)
	}

	// Print verifier feedback
	fmt.Printf("%s", obj.TcDropper.VerifierLog)

	info, _ := obj.TcDropper.Info()

	// Setup tc socket for communication with the kernel
	tcnl, err := tc.Open(&tc.Config{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not open rtnetlink socket: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		if err := tcnl.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "could not close rtnetlink socket: %v\n", err)
		}
	}()

	tcIface := "enp5s0"
	devID, err := net.InterfaceByName(tcIface)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not get interface ID: %v\n", err)
		os.Exit(1)
	}

	qdisc := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(devID.Index),
			Handle:  helper.BuildHandle(0xFFFF, 0x0000),
			Parent:  tc.HandleIngress,
		},
		Attribute: tc.Attribute{
			Kind: "clsact",
		},
	}

	// Install Qdisc on testing interface
	if err := tcnl.Qdisc().Add(&qdisc); err != nil {
		fmt.Fprintf(os.Stderr, "could not assign clsact to %s: %v\n", tcIface, err)
		os.Exit(1)
	}
	// when deleting the qdisc, the applied filter will also be gone
	defer tcnl.Qdisc().Delete(&qdisc)

	filter := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(devID.Index),
			Handle:  0,
			Parent:  helper.BuildHandle(0xFFFF, tc.HandleMinEgress),
			Info:    0x10300,
		},
		Attribute: tc.Attribute{
			Kind: "bpf",
			BPF: &tc.Bpf{
				FD:    uint32Ptr(uint32(obj.TcDropper.FD())),
				Name:  stringPtr(info.Name),
				Flags: uint32Ptr(0x1),
			},
		},
	}
	if err := tcnl.Filter().Add(&filter); err != nil {
		fmt.Fprintf(os.Stderr, "could not assign eBPF: %v\n", err)
		os.Exit(1)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)

	ticker := time.NewTicker(time.Second)
	dropPacket := true
	for {
		exit := false
		select {
		case <-ticker.C:
			fmt.Printf("===================================\n")
			iter := obj.DropMap.Iterate()
			for {
				var (
					keyOut uint32
					valOut uint64
				)
				if !iter.Next(&keyOut, &valOut) {
					if iter.Err() != nil {
						fmt.Fprintf(os.Stderr, "error while iterating map: %v\n", err)
						exit = true
					}
					break
				}
				fmt.Printf("key: %d, value: %d\n", keyOut, valOut)
				if keyOut == 123 && valOut%10 == 0 {
					dropPacket = !dropPacket
					if dropPacket {
						fmt.Printf("drop switch on\n")
						if err := obj.DropMap.Update(uint32(321), uint64(1), ebpf.UpdateAny); err != nil {
							fmt.Fprintf(os.Stderr, "error while updating drop switch: %v\n", err)
						}
					} else {
						fmt.Printf("drop switch off\n")
						if err := obj.DropMap.Update(uint32(321), uint64(0), ebpf.UpdateAny); err != nil {
							fmt.Fprintf(os.Stderr, "error while updating drop switch: %v\n", err)
						}
					}
				}
			}
		case <-sig:
			exit = true
		}

		if exit {
			break
		}
	}

	if err := tcnl.Filter().Delete(&tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(devID.Index),
			Handle:  1,
			Parent:  helper.BuildHandle(0xFFFF, tc.HandleMinEgress),
			Info:    0x10000,
		},
		Attribute: tc.Attribute{
			Kind: "bpf",
			BPF: &tc.Bpf{
				FD: uint32Ptr(uint32(obj.TcDropper.FD())),
			},
		},
	}); err != nil {
		fmt.Fprintf(os.Stderr, "could not delete eBPF filter: %v\n", err)
		os.Exit(1)
	}

}
