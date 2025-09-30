package main

import "fmt"

// PrintHelp выводит справку по доступным флагам
func PrintHelp() {
	fmt.Println("\nAvailable flags:")
	fmt.Println("  -h, --help           Show help message")
	fmt.Println("  -N, --net <addr>     Target network or IP to scan (default: local)")
	fmt.Println("  -v, --verbose        Enable verbose output")
	fmt.Println("  -V, --version        Show version info")
	fmt.Println("  -t, --timeout <sec>  Timeout in seconds (default: 5)")
	fmt.Println("  -i, --interface <if> Network interface (default: \"eth0\")")
	fmt.Println("  -o, --output <file>  Output file path")
	fmt.Println("  -c, --csv            Save result as CSV")
	fmt.Println("  -d, --debug          Enable debug mode")
	fmt.Println("  -w, --write <file>   Write captured packets to PCAP file")
	fmt.Println("  -r, --read <file>    Read packets from PCAP file instead of live capture")
	fmt.Println("		 , --cidr 					CIDR for local/non-local split in --read mode")
	fmt.Println("  -l, --local          Active ARP scan over local network (send ARP who-has to all hosts); CSV outputs only 'local' section")
	fmt.Println()
	fmt.Println("Use -h or --help to see this message again.")
}
