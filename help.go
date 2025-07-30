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
	fmt.Println("  -i, --interface <if> Network interface (default: \"default\")")
	fmt.Println("  -o, --output <file>  Output file path")
	fmt.Println("  -c, --csv            Save result as CSV")
	fmt.Println("  -n, --noping         Skip ping check")
	fmt.Println("  -d, --debug          Enable debug mode")
	fmt.Println()
	fmt.Println("Use -h or --help to see this message again.")
}
