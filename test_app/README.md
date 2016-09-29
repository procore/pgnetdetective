# Test App - Apple Pickers

This is here to give you a quick and easy way to play around with pgnetdetective.

The app is really simple. It gets all rows in the `apple_pickers` table, and then creates goroutines to automate
picking apples with a random pause. Every 5 seconds it will print who currently has picked the most apples.

## How to start the app

```bash
# Create the database
$ ./db/setup_db.sh
# Start the app
$ go run main.go
```

### Using `tcpdump` to capture the traffic

This can be done using this command:
```
tcpdump -n -s 0 -w ~/pg.cap -i any port 5432
```

### Using `pgnetdetective` to analyze the traffic

Once you have a pcap capture file, running pgnetdetective on it is as easy as:
```
pgnetdetective ~/pg.cap
```
