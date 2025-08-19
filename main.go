package main

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
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
	IP  string
	MAC string
}

var (
	deviceSeen         = make(map[string]struct{}) // глобальное множество уникальных "MAC,IP"
	deviceList         []device                    // fallback/общий список
	deviceLocalList    []device
	deviceNonLocalList []device
	localIPStr         string
	localMACStr        string
	localCIDR          *net.IPNet
	localMaskStr       string // "255.255.255.0(24)"

	readingMode bool // true, если работаем в режиме -r/--read
)

func isBroadcastMAC(mac string) bool {
	return strings.EqualFold(mac, "ff:ff:ff:ff:ff:ff")
}

// Запомнить уникальное устройство (MAC,IP); игнорируем broadcast MAC и пустые значения
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

	// Классификация: local vs non-local по localCIDR
	d := device{IP: ip, MAC: mac}
	if localCIDR != nil {
		if ipParsed := net.ParseIP(ip); ipParsed != nil && localCIDR.Contains(ipParsed) {
			deviceLocalList = append(deviceLocalList, d)
		} else {
			deviceNonLocalList = append(deviceNonLocalList, d)
		}
	} else {
		// если нет CIDR — складываем в общий список
		deviceList = append(deviceList, d)
	}
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

	// также учитываем конечные точки как уникальные устройства (MAC,IP)
	recordDevice(srcMAC, srcIP)
	recordDevice(dstMAC, dstIP)

	return true
}

// строка маски в формате 255.255.255.0(24)
func maskToString(m net.IPMask) string {
	if m == nil {
		return ""
	}
	ones, _ := m.Size()
	ip := net.IP(m)
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%s(%d)", v4.String(), ones)
	}
	return fmt.Sprintf("%s(%d)", ip.String(), ones)
}

func writeCSV() {
	// На случай, если устройства ещё не набраны напрямую, достроим из пар
	if len(pairResults) > 0 && (len(deviceLocalList)+len(deviceNonLocalList)+len(deviceList) == 0) {
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

	// === РЕЖИМ ЧТЕНИЯ PCAP БЕЗ CIDR: один список без секций ===
	if readingMode && localCIDR == nil {
		// сортируем общий список по IP, затем по MAC
		sort.Slice(deviceList, func(i, j int) bool {
			if deviceList[i].IP == deviceList[j].IP {
				return deviceList[i].MAC < deviceList[j].MAC
			}
			return ipLess(deviceList[i].IP, deviceList[j].IP)
		})
		fmt.Fprintln(f, "IP,MAC")
		for _, d := range deviceList {
			fmt.Fprintf(f, "%s,%s\n", d.IP, d.MAC)
		}
		fmt.Printf("Results written to results.csv (%d devices)\n", len(deviceList))
		return
	}

	// === Обычный режим (или read с указанным --cidr): секции local / non-local ===

	// Сортировка по IP (а при равенстве — по MAC), отдельно в списках
	sort.Slice(deviceLocalList, func(i, j int) bool {
		if deviceLocalList[i].IP == deviceLocalList[j].IP {
			return deviceLocalList[i].MAC < deviceLocalList[j].MAC
		}
		return ipLess(deviceLocalList[i].IP, deviceLocalList[j].IP)
	})
	sort.Slice(deviceNonLocalList, func(i, j int) bool {
		if deviceNonLocalList[i].IP == deviceNonLocalList[j].IP {
			return deviceNonLocalList[i].MAC < deviceNonLocalList[j].MAC
		}
		return ipLess(deviceNonLocalList[i].IP, deviceNonLocalList[j].IP)
	})
	// если fallback список использовался:
	sort.Slice(deviceList, func(i, j int) bool {
		if deviceList[i].IP == deviceList[j].IP {
			return deviceList[i].MAC < deviceList[j].MAC
		}
		return ipLess(deviceList[i].IP, deviceList[j].IP)
	})

	// Множество MAC-адресов, встретившихся в non-local (для пометки GW у local)
	nonLocalMACs := make(map[string]struct{}, len(deviceNonLocalList))
	for _, d := range deviceNonLocalList {
		nonLocalMACs[d.MAC] = struct{}{}
	}

	// Формат секциями
	fmt.Fprintln(f, "IP,MAC")
	fmt.Fprintln(f, "local")
	for _, d := range deviceLocalList {
		if _, seenOutside := nonLocalMACs[d.MAC]; seenOutside {
			// тот же MAC есть и в non-local → помечаем локальную запись как шлюз
			fmt.Fprintf(f, "%s,%s,GW\n", d.IP, d.MAC)
		} else {
			fmt.Fprintf(f, "%s,%s\n", d.IP, d.MAC)
		}
	}
	fmt.Fprintln(f, "") // пустая строка-разделитель
	fmt.Fprintln(f, "non-local")
	for _, d := range deviceNonLocalList {
		fmt.Fprintf(f, "%s,%s\n", d.IP, d.MAC)
	}
	// Если не было CIDR — выводим из fallback-списка под non-local
	if localCIDR == nil {
		for _, d := range deviceList {
			fmt.Fprintf(f, "%s,%s\n", d.IP, d.MAC)
		}
	}

	total := len(deviceLocalList) + len(deviceNonLocalList)
	if localCIDR == nil {
		total = len(deviceList)
	}
	fmt.Printf("Results written to results.csv (%d devices)\n", total)
}

func ipLess(a, b string) bool {
	ipa := net.ParseIP(a)
	ipb := net.ParseIP(b)
	if ipa == nil || ipb == nil {
		return a < b
	}
	// сравниваем как 16-байтовые адреса
	aa := ipa.To16()
	bb := ipb.To16()
	for i := 0; i < len(aa) && i < len(bb); i++ {
		if aa[i] < bb[i] {
			return true
		}
		if aa[i] > bb[i] {
			return false
		}
	}
	return len(aa) < len(bb)
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

// получить IP, MAC и сеть (CIDR) для выбранного интерфейса
func getInterfaceDetails(name string) (ipStr, macStr string, cidr *net.IPNet, err error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return "", "", nil, err
	}
	macStr = iface.HardwareAddr.String()

	addrs, err := iface.Addrs()
	if err != nil {
		return "", macStr, nil, err
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
			return ipnet.IP.String(), macStr, &net.IPNet{IP: ipnet.IP.Mask(ipnet.Mask), Mask: ipnet.Mask}, nil
		}
	}
	return "", macStr, nil, errors.New("no IPv4 on interface")
}

// глобальный путь для записи pcap (чтобы не менять сигнатуру captureMACs)
var gWritePath string

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
	writePath := flags.StringP("write", "w", "", "Write captured packets to PCAP file")
	readPath := flags.StringP("read", "r", "", "Read packets from PCAP file instead of live capture")
	cidrStr := flags.String("cidr", "", "CIDR for local/non-local split in --read mode (e.g., 192.168.1.0/24)")

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

	// режим чтения PCAP (офлайн)
	if *readPath != "" {
		readingMode = true
		// если пользователь задал --cidr — используем его для разделения
		if *cidrStr != "" {
			if _, ipnet, err := net.ParseCIDR(*cidrStr); err == nil {
				localCIDR = ipnet
				localMaskStr = maskToString(ipnet.Mask)
			} else {
				fmt.Printf("Invalid --cidr value %q: %v (will write flat list)\n", *cidrStr, err)
			}
		}
		if *verbose {
			fmt.Printf("Reading from PCAP: %s", *readPath)
			if localCIDR != nil {
				fmt.Printf("  (CIDR=%s Mask:%s)", localCIDR.String(), localMaskStr)
			}
			fmt.Println()
		}
		if err := processPCAP(*readPath); err != nil {
			log.Fatalf("Failed to read pcap: %v", err)
		}
		writeCSV()
		return
	}

	// живой захват
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

	// Получаем детали интерфейса (IP, MAC, сеть)
	var err error
	localIPStr, localMACStr, localCIDR, err = getInterfaceDetails(*iface)
	if err != nil && *verbose {
		fmt.Printf("Warning: cannot get interface details: %v\n", err)
	}
	if localCIDR != nil {
		localMaskStr = maskToString(localCIDR.Mask)
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
		fmt.Printf("  -w/--write:     %q\n", *writePath)
		fmt.Printf("  -r/--read:      %q\n", *readPath)
		fmt.Printf("  --cidr:         %q\n", *cidrStr)
		if localCIDR != nil {
			fmt.Printf("  local iface     IP: %s  MAC: %s  CIDR: %s  Mask: %s\n", localIPStr, localMACStr, localCIDR.String(), localMaskStr)
		}
		fmt.Println()
	}

	runDuration := time.Duration(*timeout) * time.Second
	gWritePath = *writePath // запомнили путь для записи pcap (если задан)
	captureMACs(*iface, 65535, true, runDuration)

	writeCSV()
}

// живой захват (с таймером); если gWritePath задан — пишем pcap
func captureMACs(iface string, snaplen int32, promisc bool, exitTimeout time.Duration) {
	const readTimeout = time.Second

	handle, err := pcap.OpenLive(iface, snaplen, promisc, readTimeout)
	if err != nil {
		log.Fatalf("pcap.OpenLive failed: %v", err)
	}
	defer handle.Close()

	// подготовка PCAP-записи (если запрошено -w)
	var pcapFile *os.File
	var pcapWriter *pcapgo.Writer
	if gWritePath != "" {
		pcapFile, err = os.Create(gWritePath)
		if err != nil {
			log.Fatalf("Cannot create pcap file %q: %v", gWritePath, err)
		}
		defer pcapFile.Close()
		pcapWriter = pcapgo.NewWriter(pcapFile)
		if err := pcapWriter.WriteFileHeader(uint32(snaplen), handle.LinkType()); err != nil {
			log.Fatalf("WriteFileHeader failed: %v", err)
		}
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()

	timer := time.NewTimer(exitTimeout)
	defer timer.Stop()

	// Обновлённая строка старта с MAC, IP и маской интерфейса
	if localIPStr != "" || localMACStr != "" {
		fmt.Printf("Capturing on %q  MAC:%s  IP:%s  Mask:%s  (will stop after %v)...\n\n", iface, localMACStr, localIPStr, localMaskStr, exitTimeout)
	} else {
		fmt.Printf("Capturing on %q (will stop after %v)...\n\n", iface, exitTimeout)
	}

	for {
		select {
		case packet, ok := <-packets:
			if !ok {
				return
			}

			// если нужно писать pcap — пишем «как есть»
			if pcapWriter != nil {
				if err := pcapWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
					log.Printf("pcap write error: %v", err)
				}
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

// офлайн обработка pcap-файла (для -r/--read)
func processPCAP(path string) error {
	fh, err := pcap.OpenOffline(path)
	if err != nil {
		return err
	}
	defer fh.Close()

	packetSource := gopacket.NewPacketSource(fh, fh.LinkType())
	fmt.Printf("Processing offline PCAP: %s\n\n", path)

	for packet := range packetSource.Packets() {
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
	}
	return nil
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
