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
	TotalResponsePackets uint
	TotalQueryPackets    uint
	seqNumbers           map[uint32]bool
}

func (qm QueryMetric) String() string {
	return fmt.Sprintf("Query: %s\nTotalNetBytes: %s\nTotalResponsePackets: %d\nTotalQueryPackets: %d\n",
		qm.Query,
		humanize.Bytes(qm.TotalNetBytes),
		qm.TotalResponsePackets,
		qm.TotalQueryPackets,
	)
}

type QueryMetrics struct {
	list  []*QueryMetric
	cache map[string]*QueryMetric
}

func (qms *QueryMetrics) Add(qm *QueryMetric, seq uint32) {
	originalQM, ok := qms.cache[qm.Query]
	if ok {
		originalQM.TotalNetBytes += qm.TotalNetBytes
		originalQM.TotalQueryPackets += 1
		originalQM.TotalResponsePackets += qm.TotalResponsePackets
		originalQM.seqNumbers[seq] = true

	} else {
		qm.seqNumbers = make(map[uint32]bool)
		qm.seqNumbers[seq] = true
		qms.list = append(qms.list, qm)
		qms.cache[qm.Query] = qm
	}
}

// For implementing sort
func (qms *QueryMetrics) Len() int {
	return len(qms.list)
}

func (qms *QueryMetrics) Less(i, j int) bool {
	return qms.list[i].TotalNetBytes < qms.list[j].TotalNetBytes
}

func (qms *QueryMetrics) Swap(i, j int) {
	qms.list[i], qms.list[j] = qms.list[j], qms.list[i]
}

func main() {
	handle, err := pcap.OpenOffline("/home/aj/Code/pgnetdetective/pgfromdb1.cap")
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

		if tcp.DstPort == 5432 {
			raw := fmt.Sprintf("%s", tcp.Payload)
			if strings.HasPrefix(raw, "P") {
				queries = append(queries, tcp)
			}
		} else if tcp.SrcPort == 5432 {
			responses = append(responses, tcp)
		}
	}

	// Dedup queries.
	combinedQueryMetrics := QueryMetrics{
		list:  []*QueryMetric{},
		cache: make(map[string]*QueryMetric),
	}
	for _, query := range queries {
		combinedQueryMetrics.Add(&QueryMetric{
			Query: normalizeQuery(fmt.Sprintf("%s", query.Payload)),
		}, query.Seq)
	}

	// Go through each QueryMetric and grab data from associated responses
	for _, query := range combinedQueryMetrics.list {
		for i := len(responses) - 1; i >= 0; i-- {
			if query.seqNumbers[responses[i].Ack] {
				query.TotalResponsePackets += 1
				query.TotalNetBytes += uint64(len(responses[i].Payload))
				responses = append(responses[:i], responses[i+1:]...)
			}
		}
	}

	// sorts by TotalNetBytes
	sort.Sort(&combinedQueryMetrics)
	for _, c := range combinedQueryMetrics.list {
		fmt.Println("******* Query *******")
		fmt.Println(c.String())
		fmt.Println("*********************")
	}

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
