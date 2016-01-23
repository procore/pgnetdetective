package metrics

import (
	"fmt"

	"github.com/dustin/go-humanize"
)

type QueryMetric struct {
	Query                string
	TotalNetBytes        uint64
	TotalResponsePackets uint
	TotalQueryPackets    uint
	// SeqNumbers is used for associating response packets with query packets.
	SeqNumbers map[uint32]bool
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
	List  []*QueryMetric
	cache map[string]*QueryMetric
}

func (qms *QueryMetrics) Add(qm *QueryMetric, seq uint32) {
	originalQM, ok := qms.cache[qm.Query]
	if ok {
		originalQM.TotalNetBytes += qm.TotalNetBytes
		originalQM.TotalQueryPackets += 1
		originalQM.TotalResponsePackets += qm.TotalResponsePackets
		originalQM.SeqNumbers[seq] = true

	} else {
		qm.SeqNumbers = make(map[uint32]bool)
		qm.SeqNumbers[seq] = true
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
