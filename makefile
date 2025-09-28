# Makefile
CC = clang
CFLAGS = -O2 -g -Wall -target bpf

.PHONY: all clean

all: drop_port.o drop_process.o problem1 problem2

drop_port.o: drop_port.c
	$(CC) $(CFLAGS) -c drop_port.c -o drop_port.o

drop_process.o: drop_process.c
	$(CC) $(CFLAGS) -c drop_process.c -o drop_process.o

problem1: drop_port.o
	go build -o problem1 problem1.go

problem2: drop_process.o
	go build -o problem2 problem2.go

clean:
	rm -f *.o problem1 problem2

install-deps:
	go mod init ebpf-packet-drop
	go get github.com/cilium/ebpf@latest
	go get golang.org/x/sys/unix@latest

run-problem1: problem1
	sudo ./problem1 -port 4040 -interface eth0

run-problem2: problem2
	sudo ./problem2 -port 4040 -process myprocess

# =====================================
# go.mod
# =====================================
# module ebpf-packet-drop
# 
# go 1.21
# 
# require (
# 	github.com/cilium/ebpf v0.12.3
# 	golang.org/x/sys v0.15.0
# )
# 
# require (
# 	golang.org/x/exp v0.0.0-20230224173230-c95f2b4c22f2 // indirect
# )