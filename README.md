# website_recorder.py: Network Traffic Analysis to record websites

This Python program, `websiteRecorder.py`, is designed to analyze network traffic from one or more .pcapng files and filter the data based on the source IP address and DNS protocol provided as a command-line argument and outputs the most frequently visited websites.

## Getting Started

Before you begin using this program, make sure you have Python 3 and Wireshark installed on your system.

### Installation

There are no specific installation steps required for this program. You can simply download the `websiteRecorder.py` file and run it using Python 3.

### Usage

To run the program, use the following command-line format:

python websiteRecorder.py [number of .pcapng files] [pcapng_file1] [ip source1] [pcapng_file2] [ip source2] ...

The packet capture files given as input in the arguement should have the extension of .pcapng along with the file name.


### Output

The output shows the list of top websites visited by each user, followed by the list of top websites visited by the users as a collective whole.
