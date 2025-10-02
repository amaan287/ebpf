package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	// Allow unlimited locking of memory for eBPF resources
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("error setting rlimit: ", err)
	}

	// Load the compiled eBPF object
	spec, err := ebpf.LoadCollectionSpec("bpf/drop.o")
	if err != nil {
		log.Fatal(err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatal(err)
	}
	defer coll.Close()

	prog := coll.Programs["drop_port"]

	// Attach to an interface
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: 2, // change to your NIC index (ip link show)
	})
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	log.Println("eBPF program loaded. Dropping packets on TCP/4040.")

	// Wait for Ctrl+C
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("Exiting, detaching program...")
}
