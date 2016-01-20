package main

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/dustin/go-humanize"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	queries   = []*layers.TCP{}
	responses = []*layers.TCP{}

	// Regex for normalize query
	fixSpaces                    = regexp.MustCompile("\\s+")
	removesBadlyEscapedQuotes    = regexp.MustCompile("\\'")
	removesBadlyEscapedQuotesTwo = regexp.MustCompile("''('')+")
	removesHex                   = regexp.MustCompile("[^\x20-\x7e]")
	removesNumbers               = regexp.MustCompile("([^a-zA-Z0-9_\\$-])-?([0-9]+)")
)

type QueryMetric struct {
	Query                string
	TotalNetBytes        uint64
	TotalResponsePackets int
	TotalQueryPackets    int
}

func (qm QueryMetric) String() string {
	return fmt.Sprintf("Query: %s\nTotalNetBytes: %s\nTotalResponsePackets: %d\nTotalQueryPackets: %d\n",
		qm.Query,
		humanize.Bytes(qm.TotalNetBytes),
		qm.TotalResponsePackets,
		qm.TotalQueryPackets,
	)
}

type QueryMetrics []QueryMetric

func (qms QueryMetrics) Len() int {
	return len(qms)
}

func (qms QueryMetrics) Less(i, j int) bool {
	return qms[i].TotalNetBytes < qms[j].TotalNetBytes
}

func (qms QueryMetrics) Swap(i, j int) {
	qms[i], qms[j] = qms[j], qms[i]
}

func main() {
	handle, err := pcap.OpenOffline("/home/aj/Code/pgnetdetective/pgsrecord.cap")
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

		// Type cast to a TCP packet
		tcp, _ := tcpLayer.(*layers.TCP)

		// Parse out relevent Query Packets
		if tcp.DstPort == 5432 {
			// Below will print it as a string.
			//fmt.Printf("TCP Packet: %s", tcp.Payload)

			raw := fmt.Sprintf("%s", tcp.Payload)
			if strings.HasPrefix(raw, "P") {
				queries = append(queries, tcp)
			}
		} else if tcp.SrcPort == 5432 {
			responses = append(responses, tcp)
		}
	}

	allQueryMetrics := QueryMetrics{}
	for _, query := range queries {
		m := QueryMetric{
			Query: normalizeQuery(fmt.Sprintf("%s", query.Payload)),
		}

		// Trick from - http://stackoverflow.com/a/29006008
		// This allows for removing responses as they are associated with a particular query.
		for i := len(responses) - 1; i >= 0; i-- {
			resp := responses[i]

			if query.Seq == resp.Ack {
				m.TotalResponsePackets += 1
				m.TotalNetBytes += uint64(len(resp.Payload))

				// Remove from list of responses
				responses = append(responses[:i], responses[i+1:]...)
			}
		}

		// Add query metric to list
		allQueryMetrics = append(allQueryMetrics, m)
	}

	// Deduplicate allQueryMetrics
	querySet := []string{}
	seen := map[string]int{}
	for _, qm := range allQueryMetrics {
		if _, ok := seen[qm.Query]; !ok {
			querySet = append(querySet, qm.Query)
			seen[qm.Query] = 1
		}
	}

	combinedQueryMetrics := QueryMetrics{}
	for _, query := range querySet {
		cm := QueryMetric{
			Query: query,
		}

		for n := len(allQueryMetrics) - 1; n >= 0; n-- {
			if allQueryMetrics[n].Query == query {
				cm.TotalQueryPackets += 1
				cm.TotalNetBytes += allQueryMetrics[n].TotalNetBytes
				cm.TotalResponsePackets += allQueryMetrics[n].TotalResponsePackets

				allQueryMetrics = append(allQueryMetrics[:n], allQueryMetrics[n+1:]...)
			}
		}

		combinedQueryMetrics = append(combinedQueryMetrics, cm)
	}

	// At the end, sort by TotalNetBytes
	sort.Sort(combinedQueryMetrics)

	for _, c := range combinedQueryMetrics {
		fmt.Println("******* Query *******")
		fmt.Println(c.String())
		fmt.Println("*********************")
	}

}

// normalizeQuery - TODO
func normalizeQuery(query string) string {
	normalizeQuery := query[1:]
	normalizeQuery = fixSpaces.ReplaceAllString(normalizeQuery, " ")
	normalizeQuery = removesBadlyEscapedQuotes.ReplaceAllString(normalizeQuery, "")
	normalizeQuery = removesBadlyEscapedQuotesTwo.ReplaceAllString(normalizeQuery, "")
	normalizeQuery = removesHex.ReplaceAllString(normalizeQuery, "")
	normalizeQuery = removesNumbers.ReplaceAllString(normalizeQuery, " 0 ")
	return normalizeQuery
}
