package Plugins

import (
	"context"
	"fmt"
	"github.com/Ullaakut/nmap"

	"time"
)

func PrintMiddlewareinfo(ip string, port string, serverports []string) {

	isin := false
	for _, serverport := range serverports {
		if port == serverport {
			isin = true
			break
		}
	}
	if !isin {

		Middlewarescan(ip, port)
	}

}

func Middlewarescan(ip string, port string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	//var arguments map[string]string

	// with a 5 minute timeout.
	scanner, err := nmap.NewScanner(
		nmap.WithTargets(ip),
		nmap.WithPorts(port),
		nmap.WithContext(ctx),

		nmap.WithScripts("http-server-header"),
	)
	if err != nil {
		return
	}

	result, _, err := scanner.Run()
	if err != nil {
		return
	}

	// Use the results to print an example output
	for _, host := range result.Hosts {
		if len(host.Ports) == 0 || len(host.Addresses) == 0 {
			continue
		}
	}
	if result.Hosts[0].Ports[0].Service.Product != "" {
		fmt.Println(ip, ":", port, "Middlewareinfo:", result.Hosts[0].Ports[0].Service.Product)
	}
}
