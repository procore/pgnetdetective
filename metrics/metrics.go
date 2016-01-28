package metrics

import (
	"fmt"
	"net"

	"github.com/dustin/go-humanize"
)

func New(query string, packets uint, srcIP net.IP, syn uint32) *QueryMetric {
	return &QueryMetric{
		Query:             query,
		TotalQueryPackets: packets,
		QueryNetUniqueIDs: []*QueryNetUniqueID{&QueryNetUniqueID{SrcIP: srcIP, Syn: syn}},
	}
}

type QueryNetUniqueID struct {
	SrcIP net.IP
	Syn   uint32
}

type QueryMetric struct {
	Query                string `json:"query"`
	TotalNetBytes        uint64
	TotalResponsePackets uint
	TotalQueryPackets    uint
	QueryNetUniqueIDs    []*QueryNetUniqueID
}

func NewQueryMetrics() *QueryMetrics {
	return &QueryMetrics{
		List:  []*QueryMetric{},
		cache: make(map[string]*QueryMetric),
	}
}

func (qm QueryMetric) String() string {
	return fmt.Sprintf("Query: %s\nTotalNetBytes: %s\nTotalResponsePackets: %d\nTotalQueryPackets: %d\n",
		qm.Query,
		humanize.Bytes(qm.TotalNetBytes),
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
	List  []*QueryMetric
	cache map[string]*QueryMetric
}

func (qms *QueryMetrics) Add(qm *QueryMetric) {
	originalQM, ok := qms.cache[qm.Query]
	if ok {
		originalQM.TotalNetBytes += qm.TotalNetBytes
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

// For implementing sort
func (qms *QueryMetrics) Len() int {
	return len(qms.List)
}

func (qms *QueryMetrics) Less(i, j int) bool {
	return qms.List[i].TotalNetBytes < qms.List[j].TotalNetBytes
}

func (qms *QueryMetrics) Swap(i, j int) {
	qms.List[i], qms.List[j] = qms.List[j], qms.List[i]
}
