package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// certData holds the SSL certificate details for a single IP address
type certData struct {
	IP                string
	CommonName        string
	Organization      string
	Country           string
	Locality          string
	Province          string
	SANsDNS           string
	SANsIP            string
	SelfSigned        bool
}

func main() {
	// Parse command-line flags
	cidrList := flag.String("l", "", "Path to file containing CIDR ranges")
	outputFile := flag.String("o", "ssdata.csv", "Output CSV file path")
	workers := flag.Int("w", 100, "Number of concurrent workers")
	timeout := flag.Duration("t", 5*time.Second, "Connection timeout")
	flag.Parse()

	if *cidrList == "" {
		log.Fatal("Please specify a CIDR list file using -l")
	}

	// Setup channels
	ipChan := make(chan net.IP, 10000)
	resultChan := make(chan *certData, 10000)

	// Start CSV writer
	go writeCSV(resultChan, *outputFile)

	// Start worker pool
	var wg sync.WaitGroup
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go worker(&wg, ipChan, resultChan, *timeout)
	}

	// Process CIDR file
	processCIDRFile(*cidrList, ipChan)

	// Wait for all workers to finish
	wg.Wait()
	close(resultChan)
}

// processCIDRFile reads CIDR ranges from a file and generates IPs
func processCIDRFile(path string, ipChan chan<- net.IP) {
	file, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var cidrWg sync.WaitGroup

	for scanner.Scan() {
		cidr := strings.TrimSpace(scanner.Text())
		if cidr == "" {
			continue
		}

		cidrWg.Add(1)
		go func(c string) {
			defer cidrWg.Done()
			generateIPs(c, ipChan)
		}(cidr)
	}

	go func() {
		cidrWg.Wait()
		close(ipChan)
	}()
}

// generateIPs generates all IPs in a CIDR range and sends them to the channel
func generateIPs(cidr string, ipChan chan<- net.IP) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		log.Printf("Error parsing CIDR %s: %v", cidr, err)
		return
	}

	ip := ipNet.IP.Mask(ipNet.Mask)
	for {
		ipCopy := make(net.IP, len(ip))
		copy(ipCopy, ip)

		ipChan <- ipCopy

		inc(ip)
		if !ipNet.Contains(ip) {
			break
		}
	}
}

// inc increments an IP address
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// worker processes IPs from the channel and scans for SSL certificates
func worker(wg *sync.WaitGroup, ipChan <-chan net.IP, resultChan chan<- *certData, timeout time.Duration) {
	defer wg.Done()

	for ip := range ipChan {
		data, err := scanIP(ip, timeout)
		if err != nil {
			continue
		}
		resultChan <- data
	}
}

// scanIP connects to an IP and retrieves SSL certificate details
func scanIP(ip net.IP, timeout time.Duration) (*certData, error) {
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: timeout},
		"tcp",
		net.JoinHostPort(ip.String(), "443"),
		&tls.Config{InsecureSkipVerify: true},
	)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Get certificate
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no certificates")
	}
	cert := state.PeerCertificates[0]

	return &certData{
		IP:                ip.String(),
		CommonName:        cert.Subject.CommonName,
		Organization:      strings.Join(cert.Subject.Organization, ", "),
		Country:           strings.Join(cert.Subject.Country, ", "),
		Locality:          strings.Join(cert.Subject.Locality, ", "),
		Province:          strings.Join(cert.Subject.Province, ", "),
		SANsDNS:           strings.Join(cert.DNSNames, ", "),
		SANsIP:            joinIPs(cert.IPAddresses),
		SelfSigned:        isSelfSigned(cert),
	}, nil
}

// joinIPs converts a slice of IPs to a comma-separated string
func joinIPs(ips []net.IP) string {
	var str []string
	for _, ip := range ips {
		str = append(str, ip.String())
	}
	return strings.Join(str, ", ")
}

// isSelfSigned checks if a certificate is self-signed
func isSelfSigned(cert *x509.Certificate) bool {
	return bytes.Equal(cert.RawIssuer, cert.RawSubject)
}

// writeCSV writes certificate data to a CSV file
func writeCSV(resultChan <-chan *certData, outputPath string) {
	file, err := os.Create(outputPath)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header
	writer.Write([]string{
		"IP Address",
		"Common Name",
		"Organization",
		"Country",
		"Locality",
		"Province",
		"Subject Alternative DNS Name",
		"Subject Alternative IP address",
		"Self-signed",
	})

	for data := range resultChan {
		writer.Write([]string{
			data.IP,
			data.CommonName,
			data.Organization,
			data.Country,
			data.Locality,
			data.Province,
			data.SANsDNS,
			data.SANsIP,
			fmt.Sprintf("%t", data.SelfSigned),
		})
		writer.Flush()
	}
}
