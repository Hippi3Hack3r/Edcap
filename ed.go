package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

var (
	pcapFile    string
	handle      *pcap.Handle
	err         error
	snapshotLen int32 = 1024 // tcpdump defults ipv4=68 ipv6=96
)

func removeSingleComm(remsrc string, remdst string, outpcap string) {
	fmt.Printf("Removing packets between %s and %s", remsrc, remdst)
	handle, err = pcap.OpenOffline(pcapFile)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	outfile, err := os.Create(outpcap)
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
	defer outfile.Close()
	w := pcapgo.NewWriter(outfile)
	defer outfile.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	w.WriteFileHeader(uint32(snapshotLen), layers.LinkTypeEthernet)

	for {
		packet, err := packetSource.NextPacket()
		if err == io.EOF {
			break
		} else if err != nil {
			log.Println("Error:", err)
			continue
		}

		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		ip, _ := ipLayer.(*layers.IPv4)
		if ip != nil {
			if (ip.SrcIP.String() == remsrc && ip.DstIP.String() == remdst) || (ip.SrcIP.String() == remdst && ip.DstIP.String() == remsrc) {
				continue
			}
		}
		w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
	}
}

func removePacketsNotTo(remsrc string, dstipnot string, outpcap string) {
	fmt.Printf("Removing packets between %s and anything but %s", remsrc, dstipnot)
	handle, err = pcap.OpenOffline(pcapFile)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	outfile, err := os.Create(outpcap)
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
	defer outfile.Close()
	w := pcapgo.NewWriter(outfile)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	w.WriteFileHeader(uint32(snapshotLen), layers.LinkTypeEthernet)

	for {
		packet, err := packetSource.NextPacket()
		if err == io.EOF {
			break
		} else if err != nil {
			log.Println("Error:", err)
			continue
		}
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		ip, _ := ipLayer.(*layers.IPv4)
		if ip != nil {
			if (ip.SrcIP.String() == remsrc && ip.DstIP.String() != dstipnot) || (ip.SrcIP.String() != dstipnot && ip.DstIP.String() == remsrc) {
				continue
			}
		}
		w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
	}
}

func removeAllTrafficFrom(remsrc string, outpcap string) {
	fmt.Printf("Removing packets to and from %s", remsrc)
	handle, err = pcap.OpenOffline(pcapFile)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	outfile, err := os.Create(outpcap)
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
	defer outfile.Close()
	w := pcapgo.NewWriter(outfile)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	w.WriteFileHeader(uint32(snapshotLen), layers.LinkTypeEthernet)

	for {
		packet, err := packetSource.NextPacket()
		if err == io.EOF {
			break
		} else if err != nil {
			log.Println("Error:", err)
			continue
		}
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		ip, _ := ipLayer.(*layers.IPv4)
		if ip != nil {
			if ip.SrcIP.String() == remsrc || ip.DstIP.String() == remsrc {
				continue
			}
		}
		w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
	}
}

func maskDomain(mask string, outpcap string) {
	fmt.Printf("Replacing all occurences of %s in dns packets", mask)
	handle, err = pcap.OpenOffline(pcapFile)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	outfile, err := os.Create(outpcap)
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
	defer outfile.Close()
	w := pcapgo.NewWriter(outfile)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	w.WriteFileHeader(uint32(snapshotLen), layers.LinkTypeEthernet)

	for {
		packet, err := packetSource.NextPacket()
		if err == io.EOF {
			break
		} else if err != nil {
			log.Println("Error:", err)
			continue
		}
		dnsLayer := packet.Layer(layers.LayerTypeDNS)
		dnss, _ := dnsLayer.(*layers.DNS)
		if dnss != nil {
			//fmt.Println("print1", packet.Metadata().CaptureInfo.Length)
			stringy := dnss.Questions[0].Name
			newquery := strings.Replace(string(stringy), mask, "fuck.this", 1)
			dnss.Questions[0].Name = []byte(newquery)

			newlen := len(stringy) - len(dnss.Questions[0].Name)
			fmt.Println("lendif", newlen)

			//fmt.Printf("%s", dnss.Questions[0])

			options := gopacket.SerializeOptions{
				ComputeChecksums: false,
				FixLengths:       true,
			}
			*packet.ApplicationLayer().(*layers.DNS) = *dnss //[]byte("Hello World!")

			// Serialize Packet to get raw bytes
			buffer := gopacket.NewSerializeBuffer()
			if err := gopacket.SerializePacket(buffer, options, packet); err != nil {
				log.Fatalln(err)
			}
			packetBytes := buffer.Bytes()
			// dfmt.Println("print2", packet.Metadata().CaptureInfo.CaptureLength)
			w.WritePacket(gopacket.CaptureInfo{Timestamp: packet.Metadata().CaptureInfo.Timestamp, Length: packet.Metadata().CaptureInfo.Length - newlen, CaptureLength: packet.Metadata().CaptureInfo.CaptureLength}, packetBytes)
		}
		//w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
	}
}

func main() {

	var purge, remsrc, remdst, dstipnot, domainmask, outfile string

	flag.StringVar(&purge, "remove-all", "0.0.0.0", "Remove all packets where this IP appears as either the src or dst")
	flag.StringVar(&domainmask, "mask-dns", "none", "replaces the domain requested with something else.")
	flag.StringVar(&remsrc, "removesrc", "none", "The source IP to remove")
	flag.StringVar(&remdst, "removedst", "none", "The destination IP to remove. If both source and dest are specified, all traffic between the two will be removerd.")
	flag.StringVar(&dstipnot, "dstipnot", "none", "An IP paired with a source to NOT remove. specifying this option along with source IP will remove all traffic that is between the source IP and anything else thats not this IP")
	flag.StringVar(&outfile, "w", "./out.pcapng", "path to save the new pcap")
	flag.StringVar(&pcapFile, "r", "", "Original pcap file to read")

	flag.Parse()

	if remdst != "none" && dstipnot != "none" {
		fmt.Println("Error: the removedst and removedst_not flags cannot be used simultaniously.")
		fmt.Println("       Get your sh*t together and come back.")
		os.Exit(0)
	}

	if domainmask != "none" {
		maskDomain(domainmask, outfile)
	} else if remsrc != "none" && remdst != "none" {
		removeSingleComm(remsrc, remdst, outfile)
	} else if remsrc != "none" && dstipnot != "none" {
		removePacketsNotTo(remsrc, dstipnot, outfile)
	} else if remsrc != "none" {
		removeAllTrafficFrom(remsrc, outfile)
	}
}
