package main

import (
	"bufio"
	"crypto/tls"
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

type result struct {
	ip           string
	cn           string
	organization string
	sans         string
}

func main() {
	cidrFile := flag.String("l", "", "Path to file containing CIDR ranges")
	outputFile := flag.String("o", "ssdata.csv", "Output CSV file path")
	workers := flag.Int("w", 100, "Number of concurrent scanning workers")
	cidrWorkers := flag.Int("c", 10, "Number of concurrent CIDR processors")
	timeout := flag.Duration("t", 5*time.Second, "Connection timeout per request")
	flag.Parse()

	if *cidrFile == "" {
		log.Fatal("Missing required -l parameter")
	}

	jobs := make(chan net.IP)
	results := make(chan result)

	// Start results writer
	go func() {
		file, err := os.Create(*outputFile)
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()

		writer := csv.NewWriter(file)
		defer writer.Flush()

		writer.Write([]string{"IP Address", "Common Name", "Organization", "SANs"})
		for res := range results {
			writer.Write([]string{res.ip, res.cn, res.organization, res.sans})
		}
	}()

	var wg sync.WaitGroup
	// Start scanning workers
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				cn, org, sans, err := getCertInfo(ip, *timeout)
				if err == nil {
					results <- result{
						ip:           ip.String(),
						cn:           cn,
						organization: org,
						sans:         sans,
					}
				}
			}
		}()
	}

	// CIDR processing pipeline
	cidrChan := make(chan string)
	var cidrWg sync.WaitGroup

	// Start CIDR workers
	for i := 0; i < *cidrWorkers; i++ {
		cidrWg.Add(1)
		go func() {
			defer cidrWg.Done()
			for cidr := range cidrChan {
				processCIDR(cidr, jobs)
			}
		}()
	}

	// Read CIDR file and distribute work
	go func() {
		file, err := os.Open(*cidrFile)
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				cidrChan <- line
			}
		}
		close(cidrChan)
		
		if err := scanner.Err(); err != nil {
			log.Fatalf("Error reading CIDR file: %v", err)
		}
	}()

	// Close jobs channel after all CIDR processing completes
	go func() {
		cidrWg.Wait()
		close(jobs)
	}()

	// Wait for all scanning to complete
	wg.Wait()
	close(results)
}

func processCIDR(cidrLine string, jobs chan<- net.IP) {
	_, ipnet, err := net.ParseCIDR(cidrLine)
	if err != nil {
		log.Printf("Skipping invalid CIDR %q: %v", cidrLine, err)
		return
	}

	ip := ipnet.IP.Mask(ipnet.Mask)
	currentIP := make(net.IP, len(ip))
	copy(currentIP, ip)

	for {
		jobs <- currentIP
		nextIP := make(net.IP, len(currentIP))
		copy(nextIP, currentIP)
		incIP(nextIP)
		if !ipnet.Contains(nextIP) {
			break
		}
		currentIP = nextIP
	}
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] != 0 {
			break
		}
	}
}

func getCertInfo(ip net.IP, timeout time.Duration) (commonName string, organization string, sans string, err error) {
	dialer := &net.Dialer{
		Timeout: timeout,
	}
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(ip.String(), "443"), &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return "", "", "", err
	}
	defer conn.Close()

	if len(conn.ConnectionState().PeerCertificates) == 0 {
		return "", "", "", fmt.Errorf("no certificates found")
	}

	cert := conn.ConnectionState().PeerCertificates[0]
	commonName = cert.Subject.CommonName
	
	if len(cert.Subject.Organization) > 0 {
		organization = strings.Join(cert.Subject.Organization, ", ")
	}

	// Get DNS names from SANs
	if len(cert.DNSNames) > 0 {
		sans = strings.Join(cert.DNSNames, ", ")
	}

	return commonName, organization, sans, nil
}
