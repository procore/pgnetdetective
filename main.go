package main

import (
	"encoding/json"
	"fmt"
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
			Name:  "json",
			Usage: "Output as json",
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

		sort.Sort(combinedQueryMetrics)

		if c.Bool("json") {
			out, err := json.Marshal(combinedQueryMetrics)
			if err != nil {
				panic(err)
			}
			os.Stdout.Write(out)
		} else {
			for _, c := range combinedQueryMetrics.List {
				fmt.Println("******* Query *******")
				fmt.Println(c.String())
				fmt.Println("*********************")
			}
		}
	}

	app.Run(os.Args)
}
