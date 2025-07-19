# Network Scanner

Simple command-line network scanner written in Go.

## Example

scanner.exe -net 192.168.1.1 -v -t 10 -i eth0

## Flags

- `-help`: Show help
- `-net`: Target network/IP
- `-v`: Verbose output
- `-V`: Version info
- `-t`: Timeout (seconds)
- `-i`: Interface
- `-o`: Output file
- `-csv`: Save output as CSV
- `-noping`: Skip ping
- `-debug`: Enable debug mode
