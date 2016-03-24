package metrics

import (
	"fmt"
	"net"
	"strconv"

	"github.com/dustin/go-humanize"
)

type QueryNetUniqueID struct {
	SrcIP net.IP
	Syn   uint32
}

type QueryMetric struct {
	Query                string              `json:"query"`
	TotalNetworkLoad     uint64              `json:"total_networkd_load"`
	TotalResponsePackets uint64              `json:"total_response_packets"`
	TotalQueryPackets    uint64              `json:"total_query_packets"`
	QueryNetUniqueIDs    []*QueryNetUniqueID `json:"-"`
}

func New(query string, packets uint64, srcIP net.IP, syn uint32) *QueryMetric {
	return &QueryMetric{
		Query:             query,
		TotalQueryPackets: packets,
		QueryNetUniqueIDs: []*QueryNetUniqueID{&QueryNetUniqueID{SrcIP: srcIP, Syn: syn}},
	}
}

func (qm QueryMetric) TotalNetworkLoadStr(displayBytes bool) string {
	if displayBytes {
		return strconv.FormatUint(qm.TotalNetworkLoad, 10)
	}
	return humanize.Bytes(qm.TotalNetworkLoad)
}

func (qm QueryMetric) String(displayBytes bool) string {
	return fmt.Sprintf("Query: %s\nTotalNetworkLoad: %s\nTotalResponsePackets: %d\nTotalQueryPackets: %d\n",
		qm.Query,
		qm.TotalNetworkLoadStr(displayBytes),
		qm.TotalResponsePackets,
		qm.TotalQueryPackets,
	)
}

func (qm QueryMetric) WasRequestFor(dstIP net.IP, ack uint32) bool {
	for _, uid := range qm.QueryNetUniqueIDs {
		if uid.SrcIP.Equal(dstIP) && uid.Syn == ack {
			return true
		}
	}
	return false
}

// QueryMetrics
type QueryMetrics struct {
	List         []*QueryMetric `json:"query_metrics"`
	cache        map[string]*QueryMetric
	DisplayBytes bool `json:"-"`
}

func NewQueryMetrics() *QueryMetrics {
	return &QueryMetrics{
		List:  []*QueryMetric{},
		cache: make(map[string]*QueryMetric),
	}
}

func (qms *QueryMetrics) Add(qm *QueryMetric) {
	originalQM, ok := qms.cache[qm.Query]
	if ok {
		originalQM.TotalNetworkLoad += qm.TotalNetworkLoad
		originalQM.TotalQueryPackets += 1
		originalQM.TotalResponsePackets += qm.TotalResponsePackets
		originalQM.QueryNetUniqueIDs = append(
			originalQM.QueryNetUniqueIDs,
			qm.QueryNetUniqueIDs...,
		)
	} else {
		qms.List = append(qms.List, qm)
		qms.cache[qm.Query] = qm
	}
}

func (qms *QueryMetrics) CsvString() [][]string {
	csvString := [][]string{
		{"query", "total_networkd_load", "total_response_packets", "total_query_packets"},
	}
	for _, qm := range qms.List {
		csvString = append(csvString, []string{
			qm.Query,
			qm.TotalNetworkLoadStr(qms.DisplayBytes),
			strconv.FormatUint(qm.TotalResponsePackets, 10),
			strconv.FormatUint(qm.TotalQueryPackets, 10),
		})
	}

	return csvString
}

func (qms *QueryMetrics) PrintText() {
	for _, qm := range qms.List {
		fmt.Println("******* Query *******")
		fmt.Println(qm.String(qms.DisplayBytes))
		fmt.Println("*********************")
	}
}

func (qms *QueryMetrics) Len() int {
	return len(qms.List)
}

// This allows for sorting to have the QueryMetrics with the highest TotalNetworkLoad at the end of the list.
func (qms *QueryMetrics) Less(i, j int) bool {
	return qms.List[i].TotalNetworkLoad < qms.List[j].TotalNetworkLoad
}

func (qms *QueryMetrics) Swap(i, j int) {
	qms.List[i], qms.List[j] = qms.List[j], qms.List[i]
}
