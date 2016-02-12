# pgnetdetective

## Requirements

Features:
* Live Capture postgres related network traffic
    * Ability to set sample rate (only grab 10% of the traffic)
    * Filters to postgres specific traffic
* Ability to process pcap data
    Format:
    * a captured .cap file
    * Live from the live capture
    Output:
    * Generate Top-Level Metrics
    * Generate Per-Query Metrics
