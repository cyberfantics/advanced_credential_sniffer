# Advanced Credential Sniffer

`advanced_credential_sniffer.py` is a Python script designed to extract credentials from network traffic captured in pcap files. It supports multiple protocols including FTP, SMTP, Telnet, and HTTP. Additionally, it can search for specific keywords in HTTP packets.

## Features

- Extracts FTP, SMTP, Telnet, and HTTP credentials.
- Searches for specific keywords in HTTP packets.
- Saves extracted data to an output file.
- Provides detailed logging and error handling.

## Requirements

- Python 3.x
- Scapy

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/cyberfantics/advanced_credential_sniffer.git
    ```

2. Navigate to the directory:
  ```bash
  cd advanced_credential_sniffer
  ```

3. Install the required Python packages:
  ```bash
pip install scapy
```

## Usage
Run the script from the command line with the required arguments:
```bash
  python advanced_credential_sniffer.py <pcap_file> <output_file> [--search <search_string>]
<pcap_file>: Path to the pcap file to be processed.
<output_file>: Path to the output file where results will be saved.
[--search <search_string>]: (Optional) String to search for in HTTP packets.
```
### Example
```bash
python advanced_credential_sniffer.py network_traffic.pcap output.txt --search CTF
```

**This command will process the network_traffic.pcap file, extract credentials, and search for the keyword "CTF" in HTTP packets. The results will be saved in output.txt.**

## Developer
Syed Mansoor ul Hassan Bukhari
