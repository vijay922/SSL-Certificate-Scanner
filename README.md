# SSL Certificate Scanner

This Go script scans IP addresses from specified CIDR ranges to retrieve SSL/TLS certificate details from port 443. The extracted information is saved in a CSV file for further analysis.

## Features
- Parses CIDR ranges and extracts all IP addresses.
- Connects to each IP on port 443 to retrieve SSL certificate details.
- Collects details like Common Name (CN), Organization, Country, Subject Alternative Names (SANs), and self-signed status.
- Uses concurrent workers for efficient scanning.
- Saves results in a CSV file.

## Usage
### Prerequisites
Ensure you have Go installed on your system. You can download it from [golang.org](https://golang.org/dl/).

### Installation
Clone this repository and navigate into the project directory:
```sh
git clone https://github.com/yourusername/ssl-cert-scanner.git
cd ssl-cert-scanner
```

### Build
To compile the binary:
```sh
go build -o sslscan
```

### Run the Scanner
```sh
./sslscan -l cidr.txt -o output.csv -w 100 -t 5s
```
**Options:**
- `-l`: Path to a file containing CIDR ranges.
- `-o`: Output CSV file path (default: `ssdata.csv`).
- `-w`: Number of concurrent workers (default: `100`).
- `-t`: Connection timeout per request (default: `5s`).

## How It Works
1. **Reads CIDR Ranges**: Loads a list of CIDR blocks from the given file.
2. **Generates IP Addresses**: Extracts all IPs from the CIDR ranges.
3. **Scans SSL Certificates**:
   - Establishes a TLS connection to port 443.
   - Retrieves SSL certificate details.
4. **Saves Results**: Writes the extracted data into a CSV file.

## Output Format
The generated CSV file includes:
| IP Address | Common Name | Organization | Country | Locality | Province | SANs (DNS) | SANs (IP) | Self-Signed |
|------------|------------|--------------|---------|----------|----------|------------|-----------|-------------|
| 192.168.1.1 | example.com | Example Corp | US | City | State | example.com, www.example.com | 192.168.1.1 | false |

## Example CIDR Input File (`cidr.txt`)
```
192.168.1.0/24
10.0.0.0/16
```

## License
This project is licensed under the MIT License.

## Contribution
Feel free to submit pull requests or report issues.

## Disclaimer
Use this tool responsibly and only on networks you have permission to scan.

