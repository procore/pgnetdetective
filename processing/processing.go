package processing

import (
	"fmt"
	"net"
	"strings"

	"github.com/procore/pgnetdetective/metrics"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type ResponsePacket struct {
	DstIP net.IP
	Ack   uint32
	Size  uint64
}

func ExtractPGPackets(handle *pcap.Handle) (*metrics.QueryMetrics, []*ResponsePacket) {
	combinedQueryMetrics := metrics.NewQueryMetrics()
	responses := []*ResponsePacket{}
	// Sorts packets into queries or responses
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	var raw string
	for packet := range packetSource.Packets() {
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			continue
		}
		ip, _ := ipLayer.(*layers.IPv4)

		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			continue
		}
		tcp, _ := tcpLayer.(*layers.TCP)

		// If the destination port is 5432...
		if tcp.DstPort == 5432 {
			// And the packet payload starts with P...
			raw = fmt.Sprintf("%s", tcp.Payload)
			if strings.HasPrefix(raw, "P") {
				// It is a (Parse) packet that contains a Query
				combinedQueryMetrics.Add(
					metrics.New(
						normalizeQuery(raw),
						1,
						ip.SrcIP,
						tcp.Seq,
					),
				)
			}
		} else if tcp.SrcPort == 5432 && tcp.ACK {
			responses = append(responses, &ResponsePacket{
				DstIP: ip.DstIP,
				Ack:   tcp.Ack,
				Size:  uint64(len(tcp.Payload)),
			},
			)
		}
	}
	return combinedQueryMetrics, responses
}

// AssociatePGPacket will go through each response and match it to a QueryMetric
func AssociatePGPackets(combinedQueryMetrics *metrics.QueryMetrics, responses []*ResponsePacket) {
	// This could be improved by implementing some sort of sequence number
	// cache, so that we could just ask it 'What QueryMetric does this seq
	// belong to?', instead of looping over the metrics every time.
	for _, query := range combinedQueryMetrics.List {
		for i := len(responses) - 1; i >= 0; i-- {
			if query.WasRequestFor(responses[i].DstIP, responses[i].Ack) {
				query.TotalResponsePackets += 1
				query.TotalNetworkLoad += responses[i].Size
				responses = append(responses[:i], responses[i+1:]...)
			}
		}
	}
}
