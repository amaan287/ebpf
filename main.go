package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

var dropProcessProgram []byte

func main() {
	var port = flag.Int("port", 4040, "Allowed TCP port for the process")
	var processName = flag.String("process", "myprocess", "Process name to filter")
	flag.Parse()

	// Remove memory limit for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load the eBPF program
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(dropProcessProgram))
	if err != nil {
		log.Fatalf("Failed to load eBPF program: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Failed to create collection: %v", err)
	}
	defer coll.Close()

	// Configure the allowed port
	portMap := coll.Maps["allowed_port_map"]
	if portMap == nil {
		log.Fatal("allowed_port_map not found in eBPF program")
	}

	key := uint32(0)
	portValue := uint32(*port)
	if err := portMap.Update(unsafe.Pointer(&key), unsafe.Pointer(&portValue), ebpf.UpdateAny); err != nil {
		log.Fatalf("Failed to update port map: %v", err)
	}

	// Configure the target process
	processMap := coll.Maps["target_process_map"]
	if processMap == nil {
		log.Fatal("target_process_map not found in eBPF program")
	}

	// Convert process name to bytes (16 bytes max for comm field)
	var processBytes [16]byte
	copy(processBytes[:], []byte(*processName))

	processKey := uint32(0)
	if err := processMap.Update(unsafe.Pointer(&processKey), unsafe.Pointer(&processBytes[0]), ebpf.UpdateAny); err != nil {
		log.Fatalf("Failed to update process map: %v", err)
	}

	// Get the cgroup program
	prog := coll.Programs["drop_process_traffic"]
	if prog == nil {
		log.Fatal("drop_process_traffic program not found")
	}

	// Attach to cgroup (system-wide socket filtering)
	cgroupPath := "/sys/fs/cgroup"
	cgroupFd, err := unix.Open(cgroupPath, unix.O_RDONLY, 0)
	if err != nil {
		log.Fatalf("Failed to open cgroup: %v", err)
	}
	defer unix.Close(cgroupFd)

	// Attach the program to cgroup
	l, err := link.AttachCgroup(link.CgroupOptions{
		Group:   cgroupFd,
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: prog,
	})
	if err != nil {
		log.Fatalf("Failed to attach to cgroup: %v", err)
	}
	defer l.Close()

	fmt.Printf("eBPF program loaded for process '%s', allowing only port %d\n", *processName, *port)
	fmt.Println("Press Ctrl+C to stop...")

	// Monitor target process PIDs
	go monitorProcess(*processName, coll.Maps["target_pid_map"])

	// Wait for interrupt signal
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c

	fmt.Println("\nDetaching eBPF program...")
}

func monitorProcess(processName string, pidMap *ebpf.Map) {
	for {
		pids := getProcessPIDs(processName)

		// Clear existing PIDs in map

		for i := uint32(0); i < 1024; i++ {
			pidMap.Delete(unsafe.Pointer(&i))
		}

		// Add current PIDs
		for i, pid := range pids {
			if i >= 1024 {
				break
			}
			key := uint32(i)
			pidValue := uint32(pid)
			pidMap.Update(unsafe.Pointer(&key), unsafe.Pointer(&pidValue), ebpf.UpdateAny)
		}

		time.Sleep(5 * time.Second)
	}
}

func getProcessPIDs(processName string) []int {
	var pids []int

	// Read /proc to find processes with matching name
	procDir, err := os.Open("/proc")
	if err != nil {
		return pids
	}
	defer procDir.Close()

	entries, err := procDir.Readdir(-1)
	if err != nil {
		return pids
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		commPath := fmt.Sprintf("/proc/%d/comm", pid)
		commData, err := os.ReadFile(commPath)
		if err != nil {
			continue
		}

		comm := strings.TrimSpace(string(commData))
		if comm == processName {
			pids = append(pids, pid)
		}
	}

	return pids
}
