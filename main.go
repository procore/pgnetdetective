package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/procore/pgnetdetective/metrics"

	"github.com/codegangsta/cli"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// TODO
// Figure out how to better associate packets
//	* Utilize timestamps?
//  * How does wireshark order its packets? (when looking at Follow TCP Stream)
// Answer: Wireshark orders the TCP Stream by timestamp. Timestamp will not be perfect, but it will be correct in most cases.
//         I am very interested in how pgbouncer knows what responses correlate to what queries.
//
// For the response packets, only grab the Data row packets

var (
	USAGE                = "USAGE: pgnetdetective /path/to/pcap/file.cap"
	combinedQueryMetrics = metrics.NewQueryMetrics()
	responses            = []*ResponsePacket{}

	// Regex for normalize query
	fixSpaces                    = regexp.MustCompile("\\s+")
	removesBadlyEscapedQuotes    = regexp.MustCompile("\\'")
	removesBadlyEscapedQuotesTwo = regexp.MustCompile("''('')+")
	removesHex                   = regexp.MustCompile("[^\x20-\x7e]")
	removesNumbers               = regexp.MustCompile("([^a-zA-Z0-9_\\$-])-?([0-9]+)")
)

type ResponsePacket struct {
	DstIP net.IP
	Ack   uint32
	Size  uint64
}

func main() {
	app := cli.NewApp()
	app.Name = "pgnetdetective"
	app.Version = "0.1"

	app.Action = func(c *cli.Context) {
		if len(c.Args()) != 1 {
			fmt.Println(USAGE)
			os.Exit(1)
		}
		path := c.Args()[0]

		// Open the .cap file
		handle, err := pcap.OpenOffline(path)
		if err != nil {
			panic(err)
		}

		// Sorts packets into queries or responses
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
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
				raw := fmt.Sprintf("%s", tcp.Payload)
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

		// Go through each response and match it to a QueryMetric
		// This could be improved by implementing some sort of sequence number
		// cache, so that we could just ask it 'What QueryMetric does this seq
		// belong to?', instead of looping over the metrics every time.
		for _, response := range responses {
			for _, query := range combinedQueryMetrics.List {
				if query.WasRequestFor(response.DstIP, response.Ack) {
					query.TotalResponsePackets += 1
					query.TotalNetBytes += response.Size
				}
			}
		}

		// sorts by TotalNetBytes
		sort.Sort(combinedQueryMetrics)
		for _, c := range combinedQueryMetrics.List {
			fmt.Println("******* Query *******")
			fmt.Println(c.String())
			fmt.Println("*********************")
		}
	}

	app.Run(os.Args)
}

// normalizeQuery is used on a raw query payload and returns a cleaned up query string.
func normalizeQuery(query string) string {
	normalizeQuery := query[1:]
	normalizeQuery = fixSpaces.ReplaceAllString(normalizeQuery, " ")
	normalizeQuery = removesBadlyEscapedQuotes.ReplaceAllString(normalizeQuery, "")
	normalizeQuery = removesBadlyEscapedQuotesTwo.ReplaceAllString(normalizeQuery, "")
	normalizeQuery = removesHex.ReplaceAllString(normalizeQuery, "")
	normalizeQuery = removesNumbers.ReplaceAllString(normalizeQuery, " 0 ")
	normalizeQuery = strings.Replace(normalizeQuery, "BDPE S", "", -1)
	return normalizeQuery
}

func getSenderTimestampFromTcpPacket(pkt *layers.TCP) (uint32, error) {
	for _, opt := range pkt.Options {
		if opt.OptionType == 8 {
			return binary.BigEndian.Uint32(opt.OptionData[:4]), nil
		}
	}
	return 0, errors.New("No timestamp found")
}
