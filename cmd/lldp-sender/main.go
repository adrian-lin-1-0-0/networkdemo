package main

import (
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	ifaceName := "lo"
	handle, err := pcap.OpenLive(ifaceName, 1600, false, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	lldp := &layers.LinkLayerDiscovery{
		ChassisID: layers.LLDPChassisID{
			Subtype: layers.LLDPChassisIDSubTypeLocal,
			ID:      net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		},
		PortID: layers.LLDPPortID{
			Subtype: layers.LLDPPortIDSubtypeLocal,
			ID:      []byte(ifaceName),
		},
		TTL: 120,
		Values: []layers.LinkLayerDiscoveryValue{
			{
				Type:  layers.LLDPTLVMgmtAddress,
				Value: []byte{0x05, 0x00, 0x00, 0x0a, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			},
		},
	}

	// Ethernet Layer (LLDP packets use specific multicast destination)
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, // Replace with your MAC
		DstMAC:       net.HardwareAddr{0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e}, // LLDP multicast address
		EthernetType: layers.EthernetTypeLinkLayerDiscovery,
	}

	// Serialize the packet
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if err := gopacket.SerializeLayers(buffer, opts, eth, lldp); err != nil {
		log.Fatal(err)
	}

	// Send the packet
	if err := handle.WritePacketData(buffer.Bytes()); err != nil {
		log.Fatal(err)
	}

	log.Println("LLDP packet sent successfully!")
}
