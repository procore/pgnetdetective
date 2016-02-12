package main

import (
	"fmt"
	"os"
	"sort"

	"github.com/codegangsta/cli"
	"github.com/google/gopacket/pcap"
)

var (
	USAGE = "USAGE: pgnetdetective pcap_file.cap"
)

func main() {
	app := cli.NewApp()
	app.Name = "pgnetdetective"
	app.Version = "0.1"

	app.Action = func(c *cli.Context) {
		if len(c.Args()) != 1 {
			fmt.Println(USAGE)
			os.Exit(1)
		}
		path := c.Args()[0]

		// Open the .cap file
		handle, err := pcap.OpenOffline(path)
		if err != nil {
			panic(err)
		}

		combinedQueryMetrics, responses := ExtractPGPackets(handle)

		AssociatePGPackets(combinedQueryMetrics, responses)

		sort.Sort(combinedQueryMetrics)

		for _, c := range combinedQueryMetrics.List {
			fmt.Println("******* Query *******")
			fmt.Println(c.String())
			fmt.Println("*********************")
		}
	}

	app.Run(os.Args)
}
