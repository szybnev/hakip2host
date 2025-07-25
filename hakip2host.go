package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	defaultWorkers = 32
	defaultDNSProtocol = "udp"
	defaultResolverPort = 53
)

// printUsage выводит справку по использованию
func printUsage() {
	fmt.Println("hakip2host - resolve IP addresses to domain names using DNS PTR and SSL certificates")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  hakip2host [options]")
	fmt.Println("  print 192.168.1.0/24 | hakip2host")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  -i, --input <ip/cidr>    Single IP address or CIDR block")
	fmt.Println("  -l, --list <file>        File containing IP addresses/CIDR blocks")
	fmt.Println("  -o, --output <file>      Save results to file")
	fmt.Println("  -s, --silent             Output only domain names")
	fmt.Println("  -h, --help               Show this help message")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  hakip2host -i 8.8.8.8")
	fmt.Println("  hakip2host -i 192.168.1.0/24")
	fmt.Println("  hakip2host -l ips.txt")
	fmt.Println("  hakip2host -s -i 8.8.8.8")
	fmt.Println("  hakip2host -o results.txt -l ips.txt")
	fmt.Println("  hakip2host -s -o domains.txt -i 8.8.8.8")
	fmt.Println("  echo '8.8.8.8' | hakip2host")
	fmt.Println()
	fmt.Println("File format (one IP/CIDR per line, # for comments):")
	fmt.Println("  192.168.1.1")
	fmt.Println("  10.0.0.0/24")
	fmt.Println("  # This is a comment")
}

// expandCIDR расширяет CIDR блок в список IP адресов
func expandCIDR(cidr string) ([]string, error) {
	if !strings.Contains(cidr, "/") {
		// Это обычный IP адрес
		if net.ParseIP(cidr) != nil {
			return []string{cidr}, nil
		}
		return nil, fmt.Errorf("invalid IP address: %s", cidr)
	}

	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	size, _ := network.Mask.Size()
	if size < 16 { // Слишком большой блок
		return nil, fmt.Errorf("CIDR block too large: %s", cidr)
	}

	var ips []string
	for ip := network.IP.Mask(network.Mask); network.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}
	
	// Удаляем network и broadcast адреса для IPv4
	if len(ips) > 2 && strings.Contains(cidr, ".") {
		ips = ips[1 : len(ips)-1]
	}

	return ips, nil
}

// inc увеличивает IP адрес на единицу
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// readInputs читает IP адреса из разных источников
func readInputs(inputFile, inputArg string) ([]string, error) {
	var inputs []string

	// Читаем из файла если указан флаг -l
	if inputFile != "" {
		file, err := os.Open(inputFile)
		if err != nil {
			return nil, fmt.Errorf("cannot open file %s: %v", inputFile, err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				inputs = append(inputs, line)
			}
		}
		if err := scanner.Err(); err != nil {
			return nil, err
		}
	}

	// Добавляем из CLI аргумента если указан флаг -i
	if inputArg != "" {
		inputs = append(inputs, inputArg)
	}

	// Если нет других источников, читаем из stdin
	if len(inputs) == 0 {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				inputs = append(inputs, line)
			}
		}
		if err := scanner.Err(); err != nil {
			return nil, err
		}
	}

	return inputs, nil
}

// extractDomain извлекает доменное имя из результата
func extractDomain(result string) string {
	parts := strings.Fields(result)
	if len(parts) >= 3 {
		return parts[2] // [TYPE] IP DOMAIN
	}
	return ""
}

// writeOutput записывает результат в консоль и файл (если указан)
func writeOutput(output string, outputFile *os.File) {
	fmt.Println(output)
	if outputFile != nil {
		outputFile.WriteString(output + "\n")
	}
}

// This function grabs the SSL certificate, then dumps the SAN and CommonName
func sslChecks(ip string, resChan chan<- string, client *http.Client) {

	url := ip

	// make sure we use https as we're doing SSL checks
	if strings.HasPrefix(ip, "http://") {
		url = strings.Replace(ip, "http://", "https://", 1)
	} else if !strings.HasPrefix(ip, "https://") {
		url = "https://" + ip
	}

	req, reqErr := http.NewRequest("HEAD", url, nil)
	if reqErr != nil {
		log.Printf("SSL check failed for %s: %v", ip, reqErr)
		return
	}

	resp, clientErr := client.Do(req)
	if clientErr != nil {
		return
	}
	defer resp.Body.Close() // Добавить закрытие

	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		dnsNames := resp.TLS.PeerCertificates[0].DNSNames
		for _, name := range dnsNames {
			resChan <- "[SSL-SAN] " + ip + " " + name
		}
		resChan <- "[SSL-CN] " + ip + " " + resp.TLS.PeerCertificates[0].Subject.CommonName
	}
}

// Do a DNS PTR lookup on the IP
func dnsChecks(ip string, resChan chan<- string, resolver *net.Resolver) {
	if resolver == nil {
		resolver = net.DefaultResolver
	}

	addr, err := resolver.LookupAddr(context.Background(), ip)
	if err != nil {
		return
	}

	for _, a := range addr {
		resChan <- "[DNS-PTR] " + ip + " " + a
	}
}

func worker(jobChan <-chan string, resChan chan<- string, wg *sync.WaitGroup, client *http.Client, resolver *net.Resolver) {
	defer wg.Done()

	for job := range jobChan {
		sslChecks(job, resChan, client)
		dnsChecks(job, resChan, resolver)
	}

}

func main() {
	listFile := flag.String("l", "", "File containing list of IP addresses/CIDR blocks")
	inputArg := flag.String("i", "", "Single IP address or CIDR block")
	outputFile := flag.String("o", "", "Save stdout to file")
	helpFlag := flag.Bool("h", false, "Show help message")
	silentFlag := flag.Bool("s", false, "Output only domain names")

	// Добавляем длинные флаги
	flag.StringVar(listFile, "list", "", "File containing list of IP addresses/CIDR blocks")
	flag.StringVar(inputArg, "input", "", "Single IP address or CIDR block")
	flag.StringVar(outputFile, "output", "", "Save stdout to file")
	flag.BoolVar(helpFlag, "help", false, "Show help message")
	flag.BoolVar(silentFlag, "silent", false, "Output only domain names")

	flag.Parse()

	// Обработка справки
	if *helpFlag {
		printUsage()
		os.Exit(0)
	}

	// Читаем входные данные
	inputs, err := readInputs(*listFile, *inputArg)
	if err != nil {
		log.Fatal(err)
	}

	// Если нет входных данных, показываем справку
	if len(inputs) == 0 {
		printUsage()
		os.Exit(0)
	}

	// Расширяем CIDR блоки в отдельные IP адреса
	var allIPs []string
	for _, input := range inputs {
		ips, err := expandCIDR(input)
		if err != nil {
			log.Printf("Error processing %s: %v", input, err)
			continue
		}
		allIPs = append(allIPs, ips...)
	}

	if len(allIPs) == 0 {
		log.Fatal("No valid IP addresses found")
	}

	// Открываем файл для записи если указан
	var outFile *os.File
	if *outputFile != "" {
		var err error
		outFile, err = os.Create(*outputFile)
		if err != nil {
			log.Fatalf("Cannot create output file %s: %v", *outputFile, err)
		}
		defer outFile.Close()
	}

	jobChan := make(chan string, 100)
	resChan := make(chan string, 100)
	done := make(chan struct{})

	// Set up TLS transport
	var transport = &http.Transport{
		Dial: (&net.Dialer{
			Timeout: 5 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 5 * time.Second,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
	}

	// Set up HTTP client
	client := &http.Client{
		Timeout:   time.Second * 10,
		Transport: transport,
	}

	// Set up DNS resolver
	resolver := net.DefaultResolver

	var wg sync.WaitGroup
	wg.Add(defaultWorkers)

	go func() {
		wg.Wait()
		close(done)
	}()

	for i := 0; i < defaultWorkers; i++ {
		go worker(jobChan, resChan, &wg, client, resolver)
	}

	// Отправляем IP адреса в канал
	go func() {
		for _, ip := range allIPs {
			jobChan <- ip
		}
		close(jobChan)
	}()

	for {
		select {
		case <-done:
			return
		case res := <-resChan:
			res = strings.TrimSuffix(res, ".")
			if *silentFlag {
				domain := extractDomain(res)
				if domain != "" {
					writeOutput(domain, outFile)
				}
			} else {
				writeOutput(res, outFile)
			}
		}
	}
}
