package main

import (
	"encoding/csv"
	"encoding/json"
	"os"
	"sort"

	"github.com/procore/pgnetdetective/metrics"
	"github.com/procore/pgnetdetective/processing"

	"github.com/codegangsta/cli"
	"github.com/google/gopacket/pcap"
)

func main() {
	app := cli.NewApp()
	app.Name = "pgnetdetective"
	app.Version = "0.1"
	app.Usage = "Analyze Postgres Network Traffic Captures"

	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "bytes",
			Usage: "Display bytes instead of as Human-Readable",
		},
		cli.BoolFlag{
			Name:  "json",
			Usage: "Output as json",
		},
		cli.BoolFlag{
			Name:  "csv",
			Usage: "Output as csv",
		},
		cli.IntFlag{
			Name:  "limit",
			Value: 0,
			Usage: "Limit output based on NetworkLoad size in kilobytes",
		},
	}

	app.Action = func(c *cli.Context) {
		if len(c.Args()) != 1 {
			cli.ShowAppHelp(c)
			os.Exit(0)
		}
		path := c.Args()[0]

		// Open the .cap file
		handle, err := pcap.OpenOffline(path)
		if err != nil {
			panic(err)
		}

		combinedQueryMetrics, responses := processing.ExtractPGPackets(handle)

		processing.AssociatePGPackets(combinedQueryMetrics, responses)

		if c.Int("limit") > 0 {
			limitedQueryMetrics := metrics.NewQueryMetrics()
			limit := uint64(c.Int("limit"))
			for _, m := range combinedQueryMetrics.List {
				if m.TotalNetworkLoad/1000 >= limit {
					limitedQueryMetrics.List = append(limitedQueryMetrics.List, m)
				}
			}
			combinedQueryMetrics = limitedQueryMetrics
		}

		combinedQueryMetrics.DisplayBytes = c.Bool("bytes")

		sort.Sort(combinedQueryMetrics)

		if c.Bool("json") {
			out, err := json.Marshal(combinedQueryMetrics)
			if err != nil {
				panic(err)
			}
			os.Stdout.Write(out)
		} else if c.Bool("csv") {
			w := csv.NewWriter(os.Stdout)
			w.WriteAll(combinedQueryMetrics.CsvString())

			if err := w.Error(); err != nil {
				panic(err)
			}
		} else {
			combinedQueryMetrics.PrintText()
		}
	}

	app.Run(os.Args)
}
