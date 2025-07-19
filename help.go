package main

import "fmt"

// Функция вывода справки по флагам
func PrintHelp() {
	fmt.Println("Usage: [flags]")
	fmt.Println("Available flags:")
	fmt.Println("  -help          Show this help message")                                // справка
	fmt.Println("  -net <CIDR/IP> Target network or IP address to scan (default: local)") // IP/сеть
	fmt.Println("  -v             Enable verbose output")                                 // подробный вывод
	fmt.Println("  -V             Show program version")                                  // версия
	fmt.Println("  -t <seconds>   Timeout in seconds (default: 5)")                       // таймаут
	fmt.Println("  -i <iface>     Network interface to use (default: \"default\")")       // интерфейс
	fmt.Println("  -o <file>      Output file to save results")                           // файл вывода
	fmt.Println("  -csv           Save results in CSV format")                            // сохранить в CSV
	fmt.Println("  -noping        Skip ping check before scanning")                       // не использовать ping
	fmt.Println("  -debug         Enable debug logging")                                  // отладка
}
