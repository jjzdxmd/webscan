package Plugins

var PluginList = map[string]interface{}{
	//"21":       FtpScan,
	//"135":      Findnet,
	//"139":      NetBIOS,
	//"445":      SmbScan,
	"1433": SqlScan,
	//"1521": OracleScan,
	"3306": SqlScan,
	//"3389":     RdpScan,
	//"5432":     PostgresScan,
	//"6379":     RedisScan,
	//"9000":     FcgiScan,
	//"11211":    MemcachedScan,
	"27017":    SqlScan,
	"1000003":  WebTitle,
	"10000031": WebTitle,
}
