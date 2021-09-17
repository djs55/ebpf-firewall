package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

type record struct {
	Flags uint32
	Dstip uint32
	Srcip uint32
}

const (
	rootCgroup      = "/sys/fs/cgroup"
	ebpfFS          = "/sys/fs/bpf"
	flowMapName     = "flows_map"
	blockedMapName  = "blocked_map"
	bpfCodePath     = "bpf.o"
	egressProgName  = "egress"
	egressLinkName  = "egress_cgroup_link"
	ingressProgName = "ingress"
	ingressLinkName = "ingress_cgroup_link"
)

func intToIP(val uint32) net.IP {
	var bytes [4]byte
	binary.LittleEndian.PutUint32(bytes[:], val)
	return net.IPv4(bytes[0], bytes[1], bytes[2], bytes[3])
}

func ipToInt(val string) uint32 {
	ip := net.ParseIP(val).To4()
	return binary.LittleEndian.Uint32(ip)
}

func main() {
	if len(os.Args) == 1 {
		fmt.Println("Give me an action: load, unload, show, block [address] or unblock [address]")
		return
	}

	unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	})

	collec, err := ebpf.LoadCollection(bpfCodePath)
	if err != nil {
		fmt.Println(err)
		return
	}

	var ingressProg, egressProg *ebpf.Program
	ingressPinPath := filepath.Join(ebpfFS, ingressProgName)
	egressPinPath := filepath.Join(ebpfFS, egressProgName)

	cgroup, err := os.Open(filepath.Join(rootCgroup, "test"))
	if err != nil {
		return
	}
	defer cgroup.Close()

	var outputMap, blockedMap *ebpf.Map
	flowPinPath := filepath.Join(ebpfFS, flowMapName)
	blockedPinPath := filepath.Join(ebpfFS, blockedMapName)

	action := os.Args[1]
	if action == "load" {
		ingressProg = collec.Programs[ingressProgName]
		ingressProg.Pin(ingressPinPath)

		egressProg = collec.Programs[egressProgName]
		egressProg.Pin(egressPinPath)

		fmt.Printf("attaching ingress to cgroup %s\n", cgroup.Name())
		l, err := link.AttachCgroup(link.CgroupOptions{
			Path:    cgroup.Name(),
			Attach:  ebpf.AttachCGroupInetIngress,
			Program: collec.Programs[ingressProgName],
		})
		if err != nil {
			fmt.Println(err)
			return
		}
		if err := l.Pin(filepath.Join(ebpfFS, ingressLinkName)); err != nil {
			panic(err)
		}
		fmt.Printf("attaching egress to cgroup %s\n", cgroup.Name())
		l, err = link.AttachCgroup(link.CgroupOptions{
			Path:    cgroup.Name(),
			Attach:  ebpf.AttachCGroupInetEgress,
			Program: collec.Programs[egressProgName],
		})
		if err != nil {
			fmt.Println(err)
			return
		}
		if err := l.Pin(filepath.Join(ebpfFS, egressLinkName)); err != nil {
			panic(err)
		}
		outputMap, _ = collec.Maps[flowMapName]
		outputMap.Pin(flowPinPath)

		blockedMap, _ = collec.Maps[blockedMapName]
		blockedMap.Pin(blockedPinPath)
		fmt.Printf("all maps pinned.\n")
	} else {
		ingressProg, err = ebpf.LoadPinnedProgram(ingressPinPath, &ebpf.LoadPinOptions{})
		if err != nil {
			fmt.Println(err)
			return
		}
		egressProg, err = ebpf.LoadPinnedProgram(egressPinPath, &ebpf.LoadPinOptions{})
		if err != nil {
			fmt.Println(err)
			return
		}

		outputMap, err = ebpf.LoadPinnedMap(flowPinPath, &ebpf.LoadPinOptions{})
		if err != nil {
			fmt.Println(err)
			return
		}
		blockedMap, err = ebpf.LoadPinnedMap(blockedPinPath, &ebpf.LoadPinOptions{})
		if err != nil {
			fmt.Println(err)
			return
		}

		if action == "show" {

			sigc := make(chan os.Signal, 1)
			signal.Notify(sigc, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
			ticker := time.NewTicker(100 * time.Millisecond)

		outer_loop:
			for {
				select {
				case <-ticker.C:
					var val record
					for outputMap.LookupAndDelete(nil, &val) == nil {
						if val.Dstip == 0 {
							continue
						}
						dstip := intToIP(val.Dstip)
						srcip := intToIP(val.Srcip)
						egress := (val.Flags & 1) != 0
						blocked := (val.Flags & 2) != 0

						var pktFlow string
						if egress {
							pktFlow = fmt.Sprintf("%v -> %v", srcip, dstip)
						} else {
							pktFlow = fmt.Sprintf("%v <- %v", dstip, srcip)
						}
						if blocked {
							pktFlow += " [BLOCKED]"
						}
						fmt.Println(pktFlow)
					}
				case <-sigc:
					break outer_loop
				}
			}
		} else if action == "unload" {
			cgroup, err := os.Open(rootCgroup)
			if err != nil {
				fmt.Println(err)
				return
			}
			defer cgroup.Close()

			ingressProg.Detach(int(cgroup.Fd()), ebpf.AttachCGroupInetIngress, 0)
			egressProg.Detach(int(cgroup.Fd()), ebpf.AttachCGroupInetEgress, 0)

			os.Remove(ingressPinPath)
			os.Remove(egressPinPath)
			os.Remove(flowPinPath)
			os.Remove(blockedPinPath)
			os.Remove(filepath.Join(ebpfFS, egressLinkName))
			os.Remove(filepath.Join(ebpfFS, ingressLinkName))
		} else if action == "block" && len(os.Args) == 3 {
			ip := ipToInt(os.Args[2])
			if err = blockedMap.Put(&ip, &ip); err != nil {
				fmt.Println(err)
			}
		} else if action == "unblock" && len(os.Args) == 3 {
			ip := ipToInt(os.Args[2])
			if err = blockedMap.Delete(&ip); err != nil {
				fmt.Println(err)
			}
		} else {
			fmt.Println("Unknown action given or wrong number of params:", action)
		}
	}
}
