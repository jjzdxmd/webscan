package Plugins

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/Ullaakut/nmap"
	"log"
	"time"
)

func PrintOsinfo(ip string) {
	isGetinfo := GetOSInfo(ip)
	for !isGetinfo {
		isGetinfo = GetOSInfo(ip)
	}
}

func GetOSInfo(targetsIP string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Equivalent to `/usr/local/bin/nmap -p 80,443,843 google.com facebook.com youtube.com`,
	// with a 5 minute timeout.
	scanner, err := nmap.NewScanner(
		nmap.WithTargets(targetsIP),
		nmap.WithPorts("22,80,445,3306,8080,8888"),
		nmap.WithOSScanGuess(),
		//nmap.WithVersionAll(),
		nmap.WithOSDetection(),
		nmap.WithContext(ctx),
	)
	if err != nil {
		log.Fatalf("unable to create nmap scanner: %v", err)
	}

	result, _, err := scanner.Run()
	if err != nil {
		log.Fatalf("unable to run nmap scan: %v", err)
	}

	//Use the results to print an example output
	//for _, host := range result.Hosts {
	//	if len(host.Ports) == 0 || len(host.Addresses) == 0 {
	//		continue
	//	}
	//
	//	fmt.Printf("Host %q:\n", host.Addresses[0])
	//
	//	for _, port := range host.Ports {
	//		fmt.Printf("\tPort %d/%s %s %s\n", port.ID, port.Protocol, port.State, port.Service.Name)
	//	}
	//}
	//fmt.Printf("Nmap done: %d hosts up scanned in %.2f seconds\n", len(result.Hosts), result.Stats.Finished.Elapsed)
	if len(result.Hosts[0].OS.Matches) == 0 {
		return false
	}
	bs, _ := json.Marshal(result.Hosts[0].OS.Matches)
	var out bytes.Buffer
	json.Indent(&out, bs, "", "\t")
	//fmt.Printf("result=%v\n", out.String())
	//fmt.Println(len(result.Hosts), "mgymgy")
	//fmt.Println(len(result.Hosts[0].OS.Matches))
	var index, maxAccuracy int
	for i, v := range result.Hosts[0].OS.Matches {
		if maxAccuracy < v.Accuracy {
			maxAccuracy, index = v.Accuracy, i
		} else {
			continue
		}
	}
	Really_info := result.Hosts[0].OS.Matches[index]
	fmt.Println("*****************---target ip os infomation---**********************")
	fmt.Println(Really_info.Name, Really_info.Classes[0].OSGeneration, Really_info.Classes[0].CPEs)
	return true
}
