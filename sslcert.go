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
	cidrList := flag.String("l", "", "Path to file containing CIDR ranges")
	outputFile := flag.String("o", "ssdata.csv", "Output CSV file path")
	workers := flag.Int("w", 500, "Number of concurrent workers") // Increased default workers
	timeout := flag.Duration("t", 3*time.Second, "Connection timeout") // Reduced default timeout
	flag.Parse()

	if *cidrList == "" {
		log.Fatal("Please specify a CIDR list file using -l")
	}

	ipChan := make(chan net.IP, 100000) // Larger buffer
	resultChan := make(chan *certData, 100000) // Larger buffer

	go writeCSV(resultChan, *outputFile)

	var wg sync.WaitGroup
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go worker(&wg, ipChan, resultChan, *timeout)
	}

	processCIDRFile(*cidrList, ipChan)

	wg.Wait()
	close(resultChan)
}

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

func generateIPs(cidr string, ipChan chan<- net.IP) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		log.Printf("Error parsing CIDR %s: %v", cidr, err)
		return
	}

	ip := ipNet.IP.Mask(ipNet.Mask)
	for {
		select {
		case ipChan <- ip.To4():
		default:
			// Prevent blocking if channel is full
			time.Sleep(100 * time.Millisecond)
		}

		inc(ip)
		if !ipNet.Contains(ip) {
			break
		}
	}
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

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

func scanIP(ip net.IP, timeout time.Duration) (*certData, error) {
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: timeout},
		"tcp",
		net.JoinHostPort(ip.String(), "443"),
		&tls.Config{
			InsecureSkipVerify: true,
			MaxVersion:         tls.VersionTLS12, // Limit to TLS 1.2 for faster handshakes
		},
	)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

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

func joinIPs(ips []net.IP) string {
	var str []string
	for _, ip := range ips {
		str = append(str, ip.String())
	}
	return strings.Join(str, ", ")
}

func isSelfSigned(cert *x509.Certificate) bool {
	return bytes.Equal(cert.RawIssuer, cert.RawSubject)
}

func writeCSV(resultChan <-chan *certData, outputPath string) {
	file, err := os.Create(outputPath)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

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

	// Batch write every 1000 records or 1 second
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	
	var buffer [][]string
	for {
		select {
		case data, ok := <-resultChan:
			if !ok {
				writer.WriteAll(buffer)
				return
			}
			buffer = append(buffer, []string{
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
			
			if len(buffer) >= 1000 {
				writer.WriteAll(buffer)
				buffer = buffer[:0]
			}
		case <-ticker.C:
			if len(buffer) > 0 {
				writer.WriteAll(buffer)
				buffer = buffer[:0]
			}
		}
	}
}
