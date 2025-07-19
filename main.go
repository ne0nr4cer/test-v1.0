package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
)

func main() {
	// Запрос ввода параметров от пользователя
	fmt.Print("Enter parameters (e.g., -net 10.0.0.1 -v -t 10 -i eth0): ")
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	args := strings.Fields(strings.TrimSpace(input))

	// Создание нового набора флагов
	fs := flag.NewFlagSet("scanner", flag.ContinueOnError)

	// Объявление поддерживаемых флагов
	help := fs.Bool("help", false, "Show help")                                  // показать справку
	version := fs.Bool("V", false, "Show program version")                       // показать версию
	verbose := fs.Bool("v", false, "Enable verbose output")                      // подробный вывод
	timeout := fs.Int("t", 5, "Timeout in seconds")                              // таймаут в секундах
	iface := fs.String("i", "default", "Network interface to use")               // сетевой интерфейс
	output := fs.String("o", "", "Output file for results")                      // файл для результатов
	csv := fs.Bool("csv", false, "Save result in CSV format")                    // сохранить в CSV
	noping := fs.Bool("noping", false, "Skip ping check")                        // не пинговать
	debug := fs.Bool("debug", false, "Enable debug mode")                        // включить отладку
	network := fs.String("net", "local", "Target network or IP address to scan") // цель сканирования

	// Парсинг введённых аргументов
	fs.Parse(args)

	// Обработка версии
	if *version {
		PrintVersion()
		os.Exit(0)
	}

	// Обработка справки
	if *help {
		PrintHelp()
		os.Exit(0)
	}

	// Вывод разобранных значений
	fmt.Println("ip:", *network)
	fmt.Println("-v (verbose):", boolToInt(*verbose))
	fmt.Println("-V (version):", boolToInt(*version))
	fmt.Println("-t (timeout):", *timeout)
	fmt.Println("-i (interface):", *iface)
	fmt.Println("-o (output file):", valueOrDefault(*output, "none"))
	fmt.Println("-csv:", boolToInt(*csv))
	fmt.Println("-noping:", boolToInt(*noping))
	fmt.Println("-debug:", boolToInt(*debug))
}

// Преобразование булевого значения в 0 или 1
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Возврат значения или значения по умолчанию, если пусто
func valueOrDefault(value, def string) string {
	if value == "" {
		return def
	}
	return value
}
