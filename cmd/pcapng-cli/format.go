package main

import "fmt"

const listHeader = "%-6s  %-30s  %-8s  %-6s  %s\n"
const listRow = "%-6d  %-30s  %-8d  %-6d  %s\n"

func packetHeader(packetNo int) string {
	if packetNo == 1 {
		return fmt.Sprintf(listHeader, "序号", "时间戳(UTC)", "抓包长度", "接口ID", "接口名")
	}
	return ""
}
