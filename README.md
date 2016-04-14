# pgnetdetective

A command line tool for converting pcap capture files (using tcpdump for example) into usable statics about your PostgreSQL network traffic.

## Installation

```
go get github.com/procore/pgnetdetective
```

## Getting Started

Once you have installed pgnetdetective, you will want to get a pcap capture file to analyize.

This can be done using this command:
```
tcpdump -n -s 0 -w ~/pg.cap -i any port 5432
```

You will want to run the above command on the machine you are concerned with (whether it be client
or server).

If you want to try it out, feel free to use the [test app](https://github.com/procore/pgnetdetective/tree/master/test_app) within this repo. It requires a little
bit of setup, but is great for seeing how the stats work.

Once you have a pcap capture file, running pgnetdetective on it is as easy as:
```
pgnetdetective ~/pg.cap
```

### Example output (from [test_app](https://github.com/procore/pgnetdetective/tree/master/test_app))



### Further options

```
$ pgnetdetective --help
NAME:
   pgnetdetective - Analyze Postgres Network Traffic Captures

USAGE:
   pgnetdetective [global options] command [command options] [arguments...]

VERSION:
   0.1

COMMANDS:
   help, h      Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --bytes              Display bytes instead of as Human-Readable
   --json               Output as json
   --csv                Output as csv
   --limit "0"          Limit output based on NetworkLoad size in kilobytes
   --help, -h           show help
   --version, -v        print the version
```

## Licence
pgnetdetective is copyright © 2015 Procore. It is free software, and may be redistributed under the terms specified in the LICENSE file.

## About Procore

<img
  src="https://www.procore.com/images/procore_logo.png"
  alt="Procore Logo"
  width="250px"
/>

pgnetdetective is maintained by Procore Technologies.

Procore - building the software that builds the world. 

Learn more about the #1 most widely used construction management software at [procore.com](https://www.procore.com/)
