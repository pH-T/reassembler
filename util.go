package reassembler

import (
	"encoding/binary"
	"math/big"

	"github.com/google/gopacket/layers"
)

func generateKeyIPV4(tcp *layers.TCP, ip *layers.IPv4) string {
	IPv4Src := big.NewInt(0)
	IPv4Src.SetBytes(ip.SrcIP.To4())

	IPv4Dst := big.NewInt(0)
	IPv4Dst.SetBytes(ip.DstIP.To4())

	spI := big.NewInt(0)
	spB := make([]byte, 2)
	binary.BigEndian.PutUint16(spB, uint16(tcp.SrcPort))
	spI.SetBytes(spB)

	dpI := big.NewInt(0)
	dpB := make([]byte, 2)
	binary.BigEndian.PutUint16(dpB, uint16(tcp.DstPort))
	dpI.SetBytes(dpB)

	x := IPv4Src.Add(IPv4Src, IPv4Dst)
	y := dpI.Add(dpI, spI)

	return x.Add(x, y).String()
}

func generateKeyIPV6(tcp *layers.TCP, ip *layers.IPv6) string {
	IPv6Src := big.NewInt(0)
	IPv6Src.SetBytes(ip.SrcIP.To16())

	IPv6IDst := big.NewInt(0)
	IPv6IDst.SetBytes(ip.DstIP.To16())

	spI := big.NewInt(0)
	spB := make([]byte, 2)
	binary.BigEndian.PutUint16(spB, uint16(tcp.SrcPort))
	spI.SetBytes(spB)

	dpI := big.NewInt(0)
	dpB := make([]byte, 2)
	binary.BigEndian.PutUint16(dpB, uint16(tcp.DstPort))
	dpI.SetBytes(dpB)

	x := IPv6Src.Add(IPv6Src, IPv6IDst)
	y := dpI.Add(dpI, spI)

	return x.Add(x, y).String()
}
