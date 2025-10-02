package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	process := flag.String("process", "myprocess", "Allowed process name")
	port := flag.Uint("port", 4040, "Allowed TCP port")
	cgroupPath := flag.String("cgroup", "/sys/fs/cgroup", "Cgroup path")
	flag.Parse()

	// Allow unlimited locked memory (required for eBPF)
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("failed to set rlimit:", err)
	}

	// Load program
	spec, err := ebpf.LoadCollectionSpec("bpf/drop_process.o")
	if err != nil {
		log.Fatal("load spec failed:", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatal("new collection failed:", err)
	}
	defer coll.Close()

	prog := coll.Programs["allow_process_connect"]
	if prog == nil {
		log.Fatal("program not found in ELF")
	}

	// Update maps with process + port
	key := uint32(0)

	// process name map
	procMap := coll.Maps["proc_name_map"]
	comm := make([]byte, 16)
	copy(comm, *process)
	if err := procMap.Put(key, comm); err != nil {
		log.Fatal("failed to set process name:", err)
	}

	// port map
	portMap := coll.Maps["port_map"]
	pval := uint16(*port)
	if err := portMap.Put(key, pval); err != nil {
		log.Fatal("failed to set port:", err)
	}

	// Attach program to cgroup
	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    *cgroupPath,
		Attach:  ebpf.AttachCGroupInet4Connect,
		Program: prog,
	})
	if err != nil {
		log.Fatal("attach failed:", err)
	}
	defer l.Close()

	log.Printf("Loaded! Only process '%s' can connect to TCP/%d", *process, *port)

	// Wait for exit
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("Detaching...")
}
