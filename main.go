package main

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/spf13/pflag"
)

type flowPair struct {
	SrcMAC, SrcIP string
	DstMAC, DstIP string
}

var (
	pairSeen    = make(map[string]struct{})
	pairResults []flowPair
)

type device struct {
	MAC string
	IP  string
}

var (
	deviceSeen = make(map[string]struct{}) // key="MAC,IP"
	deviceList []device
)

func isBroadcastMAC(mac string) bool {
	return strings.EqualFold(mac, "ff:ff:ff:ff:ff:ff")
}

func recordDevice(mac, ip string) {
	if mac == "" || ip == "" {
		return
	}
	if isBroadcastMAC(mac) {
		return
	}
	key := mac + "," + ip
	if _, ok := deviceSeen[key]; ok {
		return
	}
	deviceSeen[key] = struct{}{}
	deviceList = append(deviceList, device{MAC: mac, IP: ip})
}

func makePairKey(srcMAC, srcIP, dstMAC, dstIP string) string {
	a := srcMAC + "," + srcIP
	b := dstMAC + "," + dstIP
	if a <= b {
		return a + "||" + b
	}
	return b + "||" + a
}

func recordPair(srcMAC, srcIP, dstMAC, dstIP string) bool {
	if srcIP == "" || dstIP == "" {
		return false
	}
	key := makePairKey(srcMAC, srcIP, dstMAC, dstIP)
	if _, ok := pairSeen[key]; ok {
		return false
	}
	pairSeen[key] = struct{}{}
	pairResults = append(pairResults, flowPair{SrcMAC: srcMAC, SrcIP: srcIP, DstMAC: dstMAC, DstIP: dstIP})

	recordDevice(srcMAC, srcIP)
	recordDevice(dstMAC, dstIP)

	return true
}

func writeCSV() {
	if len(pairResults) > 0 && len(deviceList) == 0 {
		for _, p := range pairResults {
			recordDevice(p.SrcMAC, p.SrcIP)
			recordDevice(p.DstMAC, p.DstIP)
		}
	}

	f, err := os.Create("results.csv")
	if err != nil {
		log.Printf("Cannot create CSV file: %v", err)
		return
	}
	defer f.Close()

	fmt.Fprintln(f, "IP,MAC")
	for _, d := range deviceList {
		fmt.Fprintf(f, "%s,%s\n", d.IP, d.MAC)
	}
	fmt.Printf("Results written to results.csv (%d devices)\n", len(deviceList))
}

func detectDefaultInterface() (string, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range ifs {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				if ipnet.IP.To4() != nil {
					return iface.Name, nil
				}
			}
		}
	}
	return "", errors.New("no suitable interface found")
}

func main() {
	fmt.Println("You can use -h or --help to list flags.")
	fmt.Println("Example: -N 192.168.1.1 -v -t 5 -i eth0 -c")
	fmt.Print(": ")

	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	args := strings.Fields(strings.TrimSpace(line))

	flags := pflag.NewFlagSet("scanner", pflag.ContinueOnError)
	help := flags.BoolP("help", "h", false, "Show help message")
	version := flags.BoolP("version", "V", false, "Show version info")
	verbose := flags.BoolP("verbose", "v", false, "Enable verbose output")
	timeout := flags.IntP("timeout", "t", 5, "Timeout in seconds")
	iface := flags.StringP("interface", "i", "default", "Network interface to capture from")
	output := flags.StringP("output", "o", "", "Output file")
	csv := flags.BoolP("csv", "c", false, "Save result as CSV")
	noping := flags.BoolP("noping", "n", false, "Skip ping check")
	debug := flags.BoolP("debug", "d", false, "Enable debug mode")
	network := flags.StringP("net", "N", "local", "Target network or IP to scan")

	if err := flags.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, "Error parsing flags:", err)
		return
	}

	if *help {
		PrintHelp()
		return
	}
	if *version {
		PrintVersion()
		return
	}

	if *iface == "default" {
		autoIf, err := detectDefaultInterface()
		if err != nil {
			log.Fatalf("Interface detection failed: %v", err)
		}
		if *verbose {
			fmt.Printf("Auto-selected interface: %s\n", autoIf)
		}
		*iface = autoIf
	}

	if *verbose {
		fmt.Println("Parsed options:")
		fmt.Printf("  ip:             %s\n", *network)
		fmt.Printf("  -v/--verbose:   %t\n", *verbose)
		fmt.Printf("  -t/--timeout:   %d\n", *timeout)
		fmt.Printf("  -i/--interface: %s\n", *iface)
		fmt.Printf("  -o/--output:    %q\n", *output)
		fmt.Printf("  -c/--csv:       %t\n", *csv)
		fmt.Printf("  -n/--noping:    %t\n", *noping)
		fmt.Printf("  -d/--debug:     %t\n", *debug)
		fmt.Println()
	}

	runDuration := time.Duration(*timeout) * time.Second
	captureMACs(*iface, 65535, true, runDuration)

	writeCSV()
}

func captureMACs(iface string, snaplen int32, promisc bool, exitTimeout time.Duration) {
	const readTimeout = time.Second

	handle, err := pcap.OpenLive(iface, snaplen, promisc, readTimeout)
	if err != nil {
		log.Fatalf("pcap.OpenLive failed: %v", err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()

	timer := time.NewTimer(exitTimeout)
	defer timer.Stop()

	fmt.Printf("Capturing on %q (will stop after %v)...\n\n", iface, exitTimeout)
	for {
		select {
		case packet, ok := <-packets:
			if !ok {
				return
			}
			if eth := packet.Layer(layers.LayerTypeEthernet); eth != nil {
				e := eth.(*layers.Ethernet)
				if arpL := packet.Layer(layers.LayerTypeARP); arpL != nil {
					arp := arpL.(*layers.ARP)
					srcIP := net.IP(arp.SourceProtAddress).String()
					dstIP := net.IP(arp.DstProtAddress).String()
					fmt.Printf("Src MAC: %s IP: %s, Dst MAC: %s IP: %s\n",
						e.SrcMAC, srcIP, e.DstMAC, dstIP)

					recordPair(e.SrcMAC.String(), srcIP, e.DstMAC.String(), dstIP)
					continue
				}
				if ip4L := packet.Layer(layers.LayerTypeIPv4); ip4L != nil {
					ip4 := ip4L.(*layers.IPv4)
					fmt.Printf("Src MAC: %s IP: %s, Dst MAC: %s IP: %s\n",
						e.SrcMAC, ip4.SrcIP, e.DstMAC, ip4.DstIP)

					recordPair(e.SrcMAC.String(), ip4.SrcIP.String(), e.DstMAC.String(), ip4.DstIP.String())
					continue
				}
				fmt.Printf("Src MAC: %s, Dst MAC: %s\n", e.SrcMAC, e.DstMAC)
			}
		case <-timer.C:
			fmt.Printf("\nExit timeout reached (%v). Stopping capture.\n", exitTimeout)
			return
		}
	}
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func valueOrDefault(val, def string) string {
	if val == "" {
		return def
	}
	return val
}
