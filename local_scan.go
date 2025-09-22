package main

import (
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// activeScanLocal — активный ARP-скан по локальной подсети интерфейса:
// 1) формирует список всех адресов из localCIDR,
// 2) рассылает ARP who-has всем IP (по одному запросу),
// 3) параллельно слушает ARP replies и добавляет их через recordPair(),
// 4) ждёт exitTimeout для сбора ответов.
func activeScanLocal(iface string, snaplen int32, promisc bool, exitTimeout time.Duration) error {
	if localCIDR == nil || localIPStr == "" || localMACStr == "" {
		return fmt.Errorf("no interface details: IP/MAC/CIDR are empty")
	}
	srcIP := net.ParseIP(localIPStr).To4()
	srcMAC, err := net.ParseMAC(localMACStr)
	if err != nil {
		return fmt.Errorf("bad local MAC: %v", err)
	}

	handle, err := pcap.OpenLive(iface, snaplen, promisc, time.Second)
	if err != nil {
		return fmt.Errorf("pcap.OpenLive failed: %w", err)
	}
	defer handle.Close()

	// Фильтр только на ARP-ответы (op=2). Если не выйдет — продолжаем без фильтра.
	if err := handle.SetBPFFilter("arp and arp[6:2] = 2"); err != nil {
		dprintf("WARN: SetBPFFilter failed (%v), continue without filter\n", err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()

	// Чтение ARP reply
	done := make(chan struct{})
	go func() {
		for {
			select {
			case pkt, ok := <-packets:
				if !ok {
					return
				}
				if ethL := pkt.Layer(layers.LayerTypeEthernet); ethL != nil {
					e := ethL.(*layers.Ethernet)
					if arpL := pkt.Layer(layers.LayerTypeARP); arpL != nil {
						arp := arpL.(*layers.ARP)
						if arp.Operation != layers.ARPReply {
							continue
						}
						srcIP := net.IP(arp.SourceProtAddress).String()
						dstIP := net.IP(arp.DstProtAddress).String()
						dprintf("RECV  ARP reply  %s is-at %s (to %s)\n",
							srcIP, net.HardwareAddr(arp.SourceHwAddress), dstIP)
						// регистрируем (дальше CSV и группы уже сделают своё)
						recordPair(e.SrcMAC.String(), srcIP, e.DstMAC.String(), dstIP)
					}
				}
			case <-done:
				return
			}
		}
	}()

	// Рассылка ARP who-has
	targets := ipsInCIDR(localCIDR)
	dprintf("DEBUG: targets in %s: %d\n", localCIDR.String(), len(targets))
	for i, ip := range targets {
		// свой адрес можно пропустить
		if ip.Equal(srcIP) {
			continue
		}
		dprintf("SEND  ARP who-has %s  (#%d)\n", ip, i+1)
		if err := sendARPRequest(handle, srcMAC, srcIP, ip); err != nil {
			dprintf("WARN: sendARPRequest(%s) failed: %v\n", ip, err)
		}
		// консервативная пауза между кадрами (в arp-scan зависит от линка; здесь 1ms)
		time.Sleep(1 * time.Millisecond)
	}

	// Время на приём ответов
	time.Sleep(exitTimeout)
	close(done)
	return nil
}

// sendARPRequest — формирует Ethernet+ARP (Request) и отправляет в эфир
// DstMAC = ff:ff:ff:ff:ff:ff, tha=00:00:00:00:00:00, spa=srcIP, tpa=dstIP.
func sendARPRequest(handle *pcap.Handle, srcMAC net.HardwareAddr, srcIP, dstIP net.IP) error {
	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet, // 1
		Protocol:          layers.EthernetTypeIPv4, // 0x0800
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest, // 1
		SourceHwAddress:   []byte(srcMAC),
		SourceProtAddress: []byte(srcIP.To4()),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(dstIP.To4()),
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: false,
	}
	if err := gopacket.SerializeLayers(buf, opts, eth, arp); err != nil {
		return err
	}
	return handle.WritePacketData(buf.Bytes())
}

// ipsInCIDR — возвращает все IPv4-адреса в подсети (включая network/broadcast)
func ipsInCIDR(cidr *net.IPNet) []net.IP {
	if cidr == nil {
		return nil
	}
	network := cidr.IP.Mask(cidr.Mask).To4()
	if network == nil {
		return nil
	}
	ones, bits := cidr.Mask.Size()
	hostCount := 1 << uint(bits-ones)

	base := ipv4ToUint32(network)
	out := make([]net.IP, 0, hostCount)
	for i := uint32(0); i < uint32(hostCount); i++ {
		out = append(out, uint32ToIPv4(base+i))
	}
	return out
}

// утилиты для конвертаций IPv4 <-> uint32 (big endian)
func ipv4ToUint32(ip net.IP) uint32 {
	ip4 := ip.To4()
	return uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
}
func uint32ToIPv4(u uint32) net.IP {
	return net.IPv4(byte(u>>24), byte(u>>16), byte(u>>8), byte(u))
}
