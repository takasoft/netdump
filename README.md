# netdump

C program to monitor network packets on Linux 

## Build and Install

Install `libpcap` by `sudo apt-get install libpcap-dev`

Then run `make`

## Example Useage

`sudo ./netdump | tee output.txt`

Ctrl+C to quit collecting packets and show the summary

Take a look at `example-output.txt` for the example output.
