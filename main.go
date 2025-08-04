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

// detectDefaultInterface возвращает первый активный нефлаг loopback интерфейс с IPv4
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
	// Хинт и пример
	fmt.Println("You can use -h or --help to list flags.")
	fmt.Println("Example: -N 192.168.1.1 -v -t 5 -i eth0 -c")
	fmt.Print(": ")

	// Читаем строку из stdin
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	args := strings.Fields(strings.TrimSpace(line))

	// Настройка парсера флагов
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

	// Парсим введённые args
	if err := flags.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, "Error parsing flags:", err)
		return
	}

	// Обработка --help и --version
	if *help {
		PrintHelp()
		return
	}
	if *version {
		PrintVersion()
		return
	}

	// Автоопределение интерфейса, если не указан
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

	// Вывод распознанных опций в verbose режиме
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

	// Время работы = timeout секунд
	runDuration := time.Duration(*timeout) * time.Second

	// Запускаем захват и вывод MAC-адресов с общим таймаутом
	captureMACs(*iface, 65535, true, runDuration)
}

// captureMACs открывает интерфейс и печатает Src/Dst MAC каждого Ethernet-пакета,
// автоматически завершаясь по истечении указанного timeout.
// Для чтения пакетов используется readTimeout=1s.
func captureMACs(iface string, snaplen int32, promisc bool, timeout time.Duration) {
	const readTimeout = time.Second

	handle, err := pcap.OpenLive(iface, snaplen, promisc, readTimeout)
	if err != nil {
		log.Fatalf("pcap.OpenLive failed: %v", err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	fmt.Printf("Capturing on %q (will stop after %v)...\n\n", iface, timeout)
	for {
		select {
		case packet, ok := <-packets:
			if !ok {
				return
			}
			if eth := packet.Layer(layers.LayerTypeEthernet); eth != nil {
				e := eth.(*layers.Ethernet)
				fmt.Printf("Src MAC: %s, Dst MAC: %s\n", e.SrcMAC, e.DstMAC)
			}
		case <-timer.C:
			fmt.Printf("\nExit timeout reached (%v). Stopping capture.\n", timeout)
			return
		}
	}
}

// boolToInt превращает true→1, false→0
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// valueOrDefault возвращает val, если непустой, иначе def
func valueOrDefault(val, def string) string {
	if val == "" {
		return def
	}
	return val
}
