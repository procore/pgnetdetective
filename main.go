package main

import (
	"fmt"
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
// For the response packets, only grab the Data row packets

var (
	USAGE     = "USAGE: pgnetdetective /path/to/pcap/file.cap"
	queries   = []*layers.TCP{}
	responses = []*layers.TCP{}

	// Regex for normalize query
	fixSpaces                    = regexp.MustCompile("\\s+")
	removesBadlyEscapedQuotes    = regexp.MustCompile("\\'")
	removesBadlyEscapedQuotesTwo = regexp.MustCompile("''('')+")
	removesHex                   = regexp.MustCompile("[^\x20-\x7e]")
	removesNumbers               = regexp.MustCompile("([^a-zA-Z0-9_\\$-])-?([0-9]+)")
)

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
					queries = append(queries, tcp)
				}
			} else if tcp.SrcPort == 5432 {
				responses = append(responses, tcp)
			}
		}

		// Dedup queries.
		combinedQueryMetrics := metrics.NewQueryMetrics()
		for _, query := range queries {
			combinedQueryMetrics.Add(
				metrics.New(normalizeQuery(fmt.Sprintf("%s", query.Payload)), 1),
				query.Seq,
			)
		}

		// Go through each QueryMetric and grab data from associated responses
		for _, query := range combinedQueryMetrics.List {
			for i := len(responses) - 1; i >= 0; i-- {
				if query.SeqNumbers[responses[i].Ack] {
					query.TotalResponsePackets += 1
					query.TotalNetBytes += uint64(len(responses[i].Payload))
					responses = append(responses[:i], responses[i+1:]...)
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
