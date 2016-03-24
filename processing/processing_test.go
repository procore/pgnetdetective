package processing

import (
	"net"
	"testing"

	"github.com/procore/pgnetdetective/metrics"
	"github.com/stretchr/testify/assert"
)

func TestAssociatePGPackets(t *testing.T) {
	metric := &metrics.QueryMetric{
		Query: "select * from table",
		QueryNetUniqueIDs: []*metrics.QueryNetUniqueID{
			&metrics.QueryNetUniqueID{net.IPv4(111, 111, 111, 111), uint32(43212)},
		},
	}

	combinedQueryMetrics := metrics.NewQueryMetrics()
	combinedQueryMetrics.Add(metric)

	responses := []*ResponsePacket{
		&ResponsePacket{
			DstIP: net.IPv4(111, 111, 111, 111),
			Ack:   uint32(43212),
			Size:  uint64(1000),
		},
		&ResponsePacket{
			DstIP: net.IPv4(111, 111, 111, 111),
			Ack:   uint32(43212),
			Size:  uint64(1000),
		},
	}

	AssociatePGPackets(combinedQueryMetrics, responses)

	assert.Equal(t, uint64(2), combinedQueryMetrics.List[0].TotalResponsePackets)
	assert.Equal(t, uint64(2000), combinedQueryMetrics.List[0].TotalNetworkLoad)
}
