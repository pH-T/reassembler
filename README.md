# reassembler
TCP Stream reassembler in Go (IPv4 & IPv6)

## How it works

For each new TCP packet a key is generated (consisting of: SrcIP, DstIP, SrcPort, DstPort). Based on this key streams are reassembled: Each TCP stream has a unique (at least for a certain time) key and TCP packets are grouped by this key. To detect if a stream is done, each TCP packet is checked for:
- `RST` flag
- `FIN` flag

If the `RST` is found, the stream is done and gets flushed (see `.Streams()`). If the `FIN` is found and its the second seen `FIN` for this stream, it gets flushed too. For preventing memory exhaustion all streams, which have not seen a new TCP packet in 10 minutes (see `.SetFlushTime(...)`) will be flushed.

This approach does not consider out of order packets but should be "good enough" for most applications.

## Example Usage

TCP Stream reassembler which accepts pcap files (--> the path to a such a file) via POST requests.

```golang
var pcaps chan string = make(chan string, 100)

func main() {
	asm := reassembler.NewAssembler()
	asm.Run()

	go streamWorker(asm)
	go readPcapFileWorker(asm)

	defer close(pcaps)
	defer asm.Stop()

	e := echo.New()
	e.POST("/pcap", newPcapFileHandler)

	log.Println(e.Start(":8080"))

}

// streamWorker waits for finished tcp streams
func streamWorker(asm *reassembler.Assembler) {
    streams := asm.Streams()
	for {
		s, ok := <-streams
		if !ok {
			log.Println("streamWorker stopped!")
			return
        }

        // do something with the stream here

    }
}

// readPcapFileWorker feeds pcaps to the assembler
func readPcapFileWorker(asm *reassembler.Assembler) {
	for {
		select {
		case p, ok := <-pcaps:
			if !ok {
				return
			}

			handle, err := pcap.OpenOffline(p)
			if err != nil {
				log.Println(err)
				break
			}

			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			packets := packetSource.Packets()
			end := false
			for {
				select {
				case packet, ok := <-packets:
					if !ok {
						end = true
						break
					}
					if packet != nil {
						asm.Assemble(packet, p)
					}
				}

				if end {
					break
				}

			}

			log.Println("Done reading: " + p)
		}
	}
}

type PcapJSON struct {
	Path string `json:"path"`
}

func newPcapFileHandler(c echo.Context) error {
	p := new(PcapJSON)
	if err := c.Bind(p); err != nil {
		return c.String(http.StatusBadRequest, "NOK")
	}
	pcaps <- p.Path

	return c.String(http.StatusOK, "OK")
}

```

To submit a pcap-path via POST: `curl -d '{"path":"<path-to-pcap>"}' -H "Content-Type: application/json" -X POST http://localhost:8080/pcap`