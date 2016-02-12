package metrics

import (
	"net"
	"sort"

	"github.com/stretchr/testify/assert"
	"testing"
)

var wasRequestForTable = []struct {
	dstIP   net.IP
	ack     uint32
	qm      QueryMetric
	success bool
}{
	{
		dstIP: net.IPv4(123, 123, 123, 123),
		ack:   uint32(1234),
		qm: QueryMetric{
			QueryNetUniqueIDs: []*QueryNetUniqueID{
				&QueryNetUniqueID{net.IPv4(111, 111, 111, 111), uint32(43212)},
				&QueryNetUniqueID{net.IPv4(222, 111, 111, 111), uint32(432)},
				&QueryNetUniqueID{net.IPv4(123, 123, 123, 123), uint32(1234)},
			},
		},
		success: true,
	},
	{
		dstIP: net.IPv4(123, 123, 123, 123),
		ack:   uint32(1234),
		qm: QueryMetric{
			QueryNetUniqueIDs: []*QueryNetUniqueID{
				&QueryNetUniqueID{net.IPv4(123, 123, 123, 123), uint32(1234)},
			},
		},
		success: true,
	},
	{
		dstIP: net.IPv4(123, 123, 123, 123),
		ack:   uint32(1234),
		qm: QueryMetric{
			QueryNetUniqueIDs: []*QueryNetUniqueID{
				&QueryNetUniqueID{net.IPv4(111, 111, 111, 111), uint32(43212)},
				&QueryNetUniqueID{net.IPv4(222, 111, 111, 111), uint32(432)},
				&QueryNetUniqueID{net.IPv4(222, 111, 111, 111), uint32(432)},
				&QueryNetUniqueID{net.IPv4(222, 111, 111, 111), uint32(432)},
				&QueryNetUniqueID{net.IPv4(222, 111, 111, 111), uint32(432)},
				&QueryNetUniqueID{net.IPv4(222, 111, 111, 111), uint32(432)},
				&QueryNetUniqueID{net.IPv4(222, 111, 111, 111), uint32(432)},
				&QueryNetUniqueID{net.IPv4(222, 111, 111, 111), uint32(432)},
				&QueryNetUniqueID{net.IPv4(222, 111, 111, 111), uint32(432)},
				&QueryNetUniqueID{net.IPv4(123, 123, 123, 123), uint32(1234)},
			},
		},
		success: true,
	},
	{
		dstIP: net.IPv4(123, 123, 123, 123),
		ack:   uint32(1234),
		qm: QueryMetric{
			QueryNetUniqueIDs: []*QueryNetUniqueID{
				&QueryNetUniqueID{net.IPv4(111, 111, 111, 111), uint32(43212)},
				&QueryNetUniqueID{net.IPv4(222, 111, 111, 111), uint32(432)},
				&QueryNetUniqueID{net.IPv4(80, 123, 123, 123), uint32(1234)},
			},
		},
		success: false,
	},
	{
		dstIP: net.IPv4(123, 123, 123, 123),
		ack:   uint32(1234),
		qm: QueryMetric{
			QueryNetUniqueIDs: []*QueryNetUniqueID{},
		},
		success: false,
	},
	{
		dstIP: net.IPv4(123, 123, 123, 123),
		ack:   uint32(1234),
		qm: QueryMetric{
			QueryNetUniqueIDs: []*QueryNetUniqueID{
				&QueryNetUniqueID{net.IPv4(111, 111, 111, 111), uint32(43212)},
				&QueryNetUniqueID{net.IPv4(222, 111, 111, 111), uint32(432)},
				&QueryNetUniqueID{net.IPv4(121, 111, 111, 111), uint32(432)},
			},
		},
		success: false,
	},
}

func TestWasRequestFor(t *testing.T) {
	for _, test := range wasRequestForTable {
		res := test.qm.WasRequestFor(test.dstIP, test.ack)
		assert.Equal(t, test.success, res)
	}
}

func TestQueryMetricsAdd(t *testing.T) {
	qmOne := New("SELECT * from table", 1, net.IPv4(123, 123, 123, 123), uint32(123))
	qmTwo := New("SELECT * from table", 1, net.IPv4(123, 123, 123, 123), uint32(124))
	qmThree := New("SELECT * from other_table", 2, net.IPv4(124, 4, 4, 4), uint32(124))
	qmThree.TotalNetworkLoad = uint64(1000)

	combinedQueryMetrics := NewQueryMetrics()
	combinedQueryMetrics.Add(qmOne)
	combinedQueryMetrics.Add(qmTwo)
	combinedQueryMetrics.Add(qmThree)

	// Test combining the same queries.
	assert.Equal(t, 2, len(combinedQueryMetrics.List))

	sort.Sort(combinedQueryMetrics)

	assert.Equal(t, qmThree.TotalNetworkLoad, combinedQueryMetrics.List[1].TotalNetworkLoad)
}
