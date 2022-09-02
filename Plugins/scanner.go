package Plugins

import (
	"fmt"
	"github.com/shadow1ng/fscan/WebScan/lib"
	"github.com/shadow1ng/fscan/common"
	"reflect"
	"strconv"
	"strings"
	"sync"
)

func Scan(info common.HostInfo) {
	fmt.Println("start……")
	Hosts, err := common.ParseIP(info.Host)
	if err != nil {
		fmt.Println("len(hosts)==0", err)
		return
	}
	lib.Inithttp(common.Pocinfo)
	var ch = make(chan struct{}, common.Threads)
	var wg = sync.WaitGroup{}
	web := strconv.Itoa(common.PORTList["web"])
	//ms17010 := strconv.Itoa(common.PORTList["ms17010"])
	if len(Hosts) > 0 || len(common.HostPort) > 0 {
		if common.NoPing == false && len(Hosts) > 0 {
			Hosts = CheckLive(Hosts)
			fmt.Println("[jjzdxmd] 网段中存在的主机数量", len(Hosts))
		}
		if common.Scantype == "icmp" {
			common.LogWG.Wait()
			return
		}
		common.GC()
		var AlivePorts []string
		if common.Scantype == "webonly" {
			AlivePorts = NoPortScan(Hosts, info.Ports)
		} else if len(Hosts) > 0 {
			AlivePorts = PortScan(Hosts, info.Ports, common.Timeout)
			fmt.Println("[jjzdxmd] 开启的端口数为", len(AlivePorts))
			if common.Scantype == "portscan" {
				common.LogWG.Wait()
				return
			}
		}
		if len(common.HostPort) > 0 {
			AlivePorts = append(AlivePorts, common.HostPort...)
			AlivePorts = common.RemoveDuplicate(AlivePorts)
			common.HostPort = nil
			fmt.Println("[jjzdxmd] 开启的端口数为", len(AlivePorts))
		}
		common.GC()
		var severports []string //severports := []string{"21","22","135"."445","1433","3306","5432","6379","9200","11211","27017"...}
		for _, port := range common.PORTList {
			severports = append(severports, strconv.Itoa(port))
		}
		PrintOsinfo(info.Host)
		for _, targetIP := range AlivePorts {
			info.Host, info.Ports = strings.Split(targetIP, ":")[0], strings.Split(targetIP, ":")[1]
			PrintMiddlewareinfo(info.Host, info.Ports, severports)
		}
		fmt.Println("start vulscan")
		for _, targetIP := range AlivePorts {
			info.Host, info.Ports = strings.Split(targetIP, ":")[0], strings.Split(targetIP, ":")[1]
			if common.Scantype == "all" || common.Scantype == "main" {
				switch {
				//case info.Ports == "445":
				//AddScan(ms17010, info, &ch, &wg) //ms17010
				//AddScan(info.Ports, info, ch, &wg)  //smb
				//AddScan("1000002", info, ch, &wg) //smbghost
				//case info.Ports == "9000":
				//	AddScan(web, info, &ch, &wg) //http
				//AddScan(info.Ports, info, &ch, &wg) //fcgiscan

				case IsContain(severports, info.Ports):
					AddScan(info.Ports, info, &ch, &wg) //plugins scan
				default:
					AddScan(web, info, &ch, &wg) //webtitle
				}
			} else {
				scantype := strconv.Itoa(common.PORTList[common.Scantype])
				AddScan(scantype, info, &ch, &wg)
			}
		}
	}
	common.GC()
	//for _, url := range common.Urls {
	//	info.Url = url
	//	AddScan(web, info, &ch, &wg)
	//}
	common.GC()
	wg.Wait()
	common.LogWG.Wait()
	close(common.Results)
	fmt.Println(fmt.Sprintf("已完成 %v/%v", common.End, common.Num))
}

var Mutex = &sync.Mutex{}

func AddScan(scantype string, info common.HostInfo, ch *chan struct{}, wg *sync.WaitGroup) {
	*ch <- struct{}{}
	wg.Add(1)
	go func() {
		Mutex.Lock()
		common.Num += 1
		Mutex.Unlock()
		ScanFunc(&scantype, &info)
		Mutex.Lock()
		common.End += 1
		Mutex.Unlock()
		wg.Done()
		<-*ch
	}()
}

func ScanFunc(name *string, info *common.HostInfo) {
	f := reflect.ValueOf(PluginList[*name])
	in := []reflect.Value{reflect.ValueOf(info)}
	f.Call(in)
}

func IsContain(items []string, item string) bool {
	for _, eachItem := range items {
		if eachItem == item {
			return true
		}
	}
	return false
}
