package reassembler

import (
	"context"
	"fmt"
	"log"
	"os"
	"runtime"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// Stream represents a tcp stream.
type Stream struct {
	Starttime    time.Time
	Endtime      time.Time
	Endreason    string
	Packets      []gopacket.Packet
	SIP, DIP     string
	SPort, DPort uint16
	Source       string // describes the source of the pkt e.g. pcap file
}

type internalStream struct {
	Stream
	fins        int
	lastUpdated time.Time
}

// Stats is a collection of stats from the assembler
type Stats struct {
	ProcessedStreams   uint64 // how many streams have been processed
	NotTCP             uint64 // how many pkts have no TCP layer
	NotIP              uint64 // how many pkt have no IP layer
	FinishedStreams    uint64 // how many streams have been finished/reassembled
	Flushes            uint64 // how often flush was called (to flush "old" streams)
	MissingMetadata    uint64 // how often the Metadata of a packet were missing
	SeenPackets        uint64 // how many packets have been given to the assembler
	StreamsInLastFlush int    // how many open streams have been flushed in the last flush
	IPv4               uint64 // how many IPv4 pkts have been seen
	IPv6               uint64 // how many IPv6 pkts have been seen
}

type packetWithSrc struct {
	pkt gopacket.Packet
	src string // src describes where the packet was seen/found e.g. pcap file
}

// Assembler reassembles TCP streams
type Assembler struct {
	input     chan packetWithSrc
	output    chan Stream
	table     map[string]internalStream
	ctx       context.Context
	ctxCancel context.CancelFunc
	flushTime time.Duration
	stats     Stats
}

// NewAssembler creates a new assembler
func NewAssembler() *Assembler {
	asm := Assembler{}
	asm.input = make(chan packetWithSrc, 10000)          // should be big enough
	asm.output = make(chan Stream, 1000)                 // should be big enough
	asm.table = make(map[string]internalStream, 1000000) // map will be huge... avoid resizing
	ctx, cancel := context.WithCancel(context.Background())
	asm.ctx = ctx
	asm.ctxCancel = cancel
	asm.flushTime = time.Duration(10 * time.Minute)
	asm.stats = Stats{}

	return &asm
}

// SetFlushTime sets the "idle-time-limit" of a stream e.g. the time no new packet for a stream was found.
// After this time the stream will be flushed.
// Needs a positive value!
// Set this value before calling Run()!
// Default: 10 --> streams with no new packets since 10 minutes will be flushed.
func (a *Assembler) SetFlushTime(value int) {
	if value < 0 {
		return
	}
	a.flushTime = time.Duration(value)
}

// Stats returnes the stats of the assembler.
// This call is not protected by a mutex... should work nevertheless in this case but its 'undefined' behaviour.
func (a *Assembler) Stats() Stats {
	return a.stats
}

// Assemble feeds a gopacket.Packet to the assembler. Only packets which have a ipv*Layer AND a tcpLayer will be processed.
// This call might block.
func (a *Assembler) Assemble(packet gopacket.Packet, src string) {
	//go func() { a.input <- packet }() // TODO: evaluate if this (go...) is a good idea or if it should block
	a.input <- packetWithSrc{packet, src}
}

// Run starts the assembler. Call this only once!
func (a *Assembler) Run() {
	go func() {
		ticker := time.NewTicker(60 * time.Second) // check every 60 secs if a flush should be done
		for {
			select {
			case packet, ok := <-a.input:
				if !ok {
					log.Println("STOPPED (via channel...)")
					return
				}

				a.stats.SeenPackets++

				var key string
				var ipSrcString string
				var ipDstString string
				var tcp *layers.TCP

				// packet layer checks
				ipv4Layer := packet.pkt.Layer(layers.LayerTypeIPv4)
				if ipv4Layer == nil { // its not IPv4 - check if IPv6
					ipv6Layer := packet.pkt.Layer(layers.LayerTypeIPv6)
					if ipv6Layer == nil { // no IPv*layer
						a.stats.NotIP++
						break
					}

					ip, ok := ipv6Layer.(*layers.IPv6)
					if !ok {
						a.stats.NotIP++
						break
					}
					ipSrcString = ip.SrcIP.String()
					ipDstString = ip.DstIP.String()

					tcpLayer := packet.pkt.Layer(layers.LayerTypeTCP)
					if tcpLayer == nil {
						a.stats.NotTCP++
						break
					}

					tcp, ok = tcpLayer.(*layers.TCP)
					if !ok {
						a.stats.NotTCP++
						break
					}
					a.stats.IPv6++
					key = generateKeyIPV6(tcp, ip)
				} else {
					ip, ok := ipv4Layer.(*layers.IPv4)
					if !ok {
						a.stats.NotIP++
						break
					}
					ipSrcString = ip.SrcIP.String()
					ipDstString = ip.DstIP.String()

					tcpLayer := packet.pkt.Layer(layers.LayerTypeTCP)
					if tcpLayer == nil {
						a.stats.NotTCP++
						break
					}

					tcp, ok = tcpLayer.(*layers.TCP)
					if !ok {
						a.stats.NotTCP++
						break
					}
					a.stats.IPv4++
					key = generateKeyIPV4(tcp, ip)
				}

				elem, ok := a.table[key]
				if !ok { // new stream
					a.stats.ProcessedStreams++
					tmpInternalStream := internalStream{}

					if packet.pkt.Metadata() != nil {
						tmpInternalStream.Starttime = packet.pkt.Metadata().Timestamp
						tmpInternalStream.Endtime = packet.pkt.Metadata().Timestamp
					} else {
						a.stats.MissingMetadata++
						tmpInternalStream.Starttime = time.Now()
						tmpInternalStream.Endtime = time.Now()
					}

					tmpInternalStream.Source = packet.src
					tmpInternalStream.SIP = ipSrcString
					tmpInternalStream.DIP = ipDstString
					tmpInternalStream.SPort = uint16(tcp.SrcPort)
					tmpInternalStream.DPort = uint16(tcp.DstPort)
					tmpInternalStream.Packets = append(tmpInternalStream.Packets, packet.pkt)
					tmpInternalStream.lastUpdated = time.Now()
					a.table[key] = tmpInternalStream
					break
				}

				if tcp.RST { // we found a RST for this existing Stream
					elem.Packets = append(elem.Packets, packet.pkt)
					if packet.pkt.Metadata() != nil {
						elem.Endtime = packet.pkt.Metadata().Timestamp
					} else {
						a.stats.MissingMetadata++
						elem.Endtime = time.Now()
					}
					elem.Endreason = "RST"
					elem.lastUpdated = time.Now()
					a.output <- elem.Stream
					a.stats.FinishedStreams++
					delete(a.table, key)
					break
				}

				if tcp.FIN { // we found a FIN
					elem.fins++
					elem.Packets = append(elem.Packets, packet.pkt)
					elem.lastUpdated = time.Now()
					if elem.fins == 2 { // check if its the second one
						if packet.pkt.Metadata() != nil {
							elem.Endtime = packet.pkt.Metadata().Timestamp
						} else {
							a.stats.MissingMetadata++
							elem.Endtime = time.Now()
						}
						elem.Endreason = "fin"
						a.output <- elem.Stream
						a.stats.FinishedStreams++
						delete(a.table, key)
						break
					}
					a.table[key] = elem
				}

				elem.Packets = append(elem.Packets, packet.pkt)
				elem.lastUpdated = time.Now()
				a.table[key] = elem

			case <-ticker.C:
				a.stats.Flushes++
				x1 := len(a.table)
				for k, s := range a.table {
					if time.Now().After(s.lastUpdated.Add(a.flushTime)) {
						// its time to flush this stream
						s.Endreason = "timeout"
						a.output <- s.Stream
						a.stats.FinishedStreams++
						delete(a.table, k)
					}
				}
				a.stats.StreamsInLastFlush = (x1 - len(a.table))
				log.Printf("Flushed: %d/%d streams\n", a.stats.StreamsInLastFlush, x1)
				runtime.GC()

			case <-a.ctx.Done():
				log.Println("STOPPED")
				return
			}

		}

	}()
}

// Stop stops the assembler.
func (a *Assembler) Stop() {
	a.ctxCancel()
	close(a.input)
	close(a.output)
}

// Streams returnes the next available stream or ok == false if no streams are available.
// Try to consume and recall this functions as fast as possible otherwise the reassembler might block.
func (a *Assembler) Streams() chan Stream {
	return a.output
}

// DummyWorker is a dummy for testing... use Streams() for real stuff
func (a *Assembler) DummyWorker() {
	//open a new pcap
	n := fmt.Sprintf("flows_%d", time.Now().UnixNano()) + ".pcap"
	f, err := os.Create(n)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	log.Println("New file: " + n)
	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(65535, layers.LinkTypeIPv4) // for some pcaps LinkTypeEthernet/LinkTypeIPv6 is needed

	for {
		select {
		case stream, ok := <-a.output:
			if !ok {
				return
			}

			for _, pkt := range stream.Packets {
				err := w.WritePacket(pkt.Metadata().CaptureInfo, pkt.Data())
				if err != nil {
					log.Fatal(err)
				}
			}

		}
	}
}
