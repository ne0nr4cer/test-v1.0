package main

import "fmt"

func PrintHelp() {
	fmt.Println("Usage: [flags]")
	fmt.Println("Available flags:")
	fmt.Println("  -help          Show this help message")
	fmt.Println("  -net <CIDR/IP> Target network or IP address to scan (default: local)")
	fmt.Println("  -v             Enable verbose output")
	fmt.Println("  -V             Show program version")
	fmt.Println("  -t <seconds>   Timeout in seconds (default: 5)")
	fmt.Println("  -i <iface>     Network interface to use (default: \"default\")")
	fmt.Println("  -o <file>      Output file to save results")
	fmt.Println("  -csv           Save results in CSV format")
	fmt.Println("  -noping        Skip ping check before scanning")
	fmt.Println("  -debug         Enable debug logging")
}
