package Plugins

import (
	"context"
	"fmt"
	"github.com/Ullaakut/nmap"
	"github.com/shadow1ng/fscan/common"
	"log"
	"time"
)

func SqlScan(info *common.HostInfo) (tmperr error) {
	//if common.IsBrute {
	//	return
	//}
	//starttime := time.Now().Unix()
	//for _, user := range common.Userdict["mysql"] {
	//	for _, pass := range common.Passwords {
	//		pass = strings.Replace(pass, "{user}", user, -1)
	//		flag, err := MysqlConn(info, user, pass)
	//		if flag == true && err == nil {
	//			return err
	//		} else {
	//			errlog := fmt.Sprintf("[-] mysql %v:%v %v %v %v", info.Host, info.Ports, user, pass, err)
	//			common.LogError(errlog)
	//			tmperr = err
	//			if common.CheckErrs(err) {
	//				return err
	//			}
	//			if time.Now().Unix()-starttime > (int64(len(common.Userdict["mysql"])*len(common.Passwords)) * common.Timeout) {
	//				return err
	//			}
	//		}
	//	}
	//}
	//return tmperr
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Equivalent to `/usr/local/bin/nmap -p 80,443,843 google.com facebook.com youtube.com`,
	// with a 5 minute timeout.
	scanner, err := nmap.NewScanner(
		nmap.WithTargets(info.Host),
		nmap.WithPorts(info.Ports),
		nmap.WithContext(ctx),
		//nmap.WithVersionAll(),
		//nmap.WithVersionIntensity(9),
		//nmap.WithVersionTrace(),
		nmap.WithServiceInfo(),
	)
	if err != nil {
		log.Fatalf("unable to create nmap scanner: %v", err)
	}

	result, _, err := scanner.Run()
	if err != nil {
		log.Fatalf("unable to run nmap scan: %v", err)
	}

	// Use the results to print an example output
	for _, host := range result.Hosts {
		if len(host.Ports) == 0 || len(host.Addresses) == 0 {
			continue
		}

		// fmt.Printf("Host %q:\n", host.Addresses[0])

		// for _, port := range host.Ports {
		// 	fmt.Printf("\tPort %d/%s %s %s\n", port.ID, port.Protocol, port.State, port.Service.Name)
		// }
	}
	// bs, _ := json.Marshal(result)
	// var out bytes.Buffer
	// json.Indent(&out, bs, "", "\t")
	// fmt.Printf("result=%v\n", out.String())
	if info.Ports == "3306" {
		fmt.Println(info.Host, "Port:", info.Ports, "MySQL Version:", result.Hosts[0].Ports[0].Service.Version)
	} else if info.Ports == "1433" {
		fmt.Println(info.Host, "Port:", info.Ports, "MSSQL Version:", result.Hosts[0].Ports[0].Service.Version)
	} else if info.Ports == "27017" {
		fmt.Println(info.Host, "Port:", info.Ports, "MongoDB Version:", result.Hosts[0].Ports[0].Service.Version)
	}
	return err
}

//func MysqlConn(info *common.HostInfo, user string, pass string) (flag bool, err error) {
//	flag = false
//	Host, Port, Username, Password := info.Host, info.Ports, user, pass
//	dataSourceName := fmt.Sprintf("%v:%v@tcp(%v:%v)/mysql?charset=utf8&timeout=%v", Username, Password, Host, Port, time.Duration(common.Timeout)*time.Second)
//	db, err := sql.Open("mysql", dataSourceName)
//	if err == nil {
//		db.SetConnMaxLifetime(time.Duration(common.Timeout) * time.Second)
//		db.SetConnMaxIdleTime(time.Duration(common.Timeout) * time.Second)
//		db.SetMaxIdleConns(0)
//		defer db.Close()
//		err = db.Ping()
//		if err == nil {
//			result := fmt.Sprintf("[+] mysql:%v:%v:%v %v", Host, Port, Username, Password)
//			common.LogSuccess(result)
//			flag = true
//		}
//	}
//	return flag, err
//}
