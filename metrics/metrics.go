package metrics

import (
	"fmt"
	"net"

	"github.com/dustin/go-humanize"
)

type QueryNetUniqueID struct {
	SrcIP net.IP
	Syn   uint32
}

type QueryMetric struct {
	Query                string              `json:"query"`
	TotalNetworkLoad     uint64              `json:"total_net_bytes"`
	TotalResponsePackets uint                `json:"total_response_packets"`
	TotalQueryPackets    uint                `json:"total_query_packets"`
	QueryNetUniqueIDs    []*QueryNetUniqueID `json:"-"`
}

func New(query string, packets uint, srcIP net.IP, syn uint32) *QueryMetric {
	return &QueryMetric{
		Query:             query,
		TotalQueryPackets: packets,
		QueryNetUniqueIDs: []*QueryNetUniqueID{&QueryNetUniqueID{SrcIP: srcIP, Syn: syn}},
	}
}

func (qm QueryMetric) String() string {
	return fmt.Sprintf("Query: %s\nTotalNetworkLoad: %s\nTotalResponsePackets: %d\nTotalQueryPackets: %d\n",
		qm.Query,
		humanize.Bytes(qm.TotalNetworkLoad),
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
	List  []*QueryMetric          `json:"query_metrics"`
	cache map[string]*QueryMetric `json:"-"`
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

func (qms *QueryMetrics) Len() int {
	return len(qms.List)
}

func (qms *QueryMetrics) Less(i, j int) bool {
	return qms.List[i].TotalNetworkLoad < qms.List[j].TotalNetworkLoad
}

func (qms *QueryMetrics) Swap(i, j int) {
	qms.List[i], qms.List[j] = qms.List[j], qms.List[i]
}
