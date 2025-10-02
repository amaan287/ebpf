package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	// CLI flags
	ifaceName := flag.String("iface", "", "Network interface to attach XDP program")
	port := flag.Uint("port", 4040, "TCP port to drop")
	flag.Parse()

	if *ifaceName == "" {
		log.Fatal("You must provide an interface name with --iface")
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("error setting rlimit", err)
	}

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
	if prog == nil {
		log.Fatal("eBPF program 'drop_port' not found")
	}

	iface, err := net.InterfaceByName(*ifaceName)
	if err != nil {
		log.Fatalf("could not get interface %s: %v", *ifaceName, err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	log.Printf("eBPF program loaded. Dropping TCP packets on port %d at interface %s.\n", *port, *ifaceName)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("Exiting, detaching program...")
}
