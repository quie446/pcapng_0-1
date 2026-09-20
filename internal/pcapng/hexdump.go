package pcapng

import (
	"fmt"
	"io"
	"strings"
)

// HexDump writes data in canonical xxd style:
// 00000000  45 00 00 73 00 00 40 00  40 11 b4 2e c0 a8 00 01  E..s.@.@.......
func HexDump(w io.Writer, data []byte, max int) error {
	if max >= 0 && max < len(data) {
		data = data[:max]
	}
	var b strings.Builder
	for off := 0; off < len(data); off += 16 {
		end := off + 16
		if end > len(data) {
			end = len(data)
		}
		fmt.Fprintf(&b, "%08x  ", off)
		row := data[off:end]
		for i := 0; i < 16; i++ {
			if i < len(row) {
				fmt.Fprintf(&b, "%02x ", row[i])
			} else {
				b.WriteString("   ")
			}
			if i == 7 {
				b.WriteByte(' ')
			}
		}
		b.WriteByte(' ')
		for _, c := range row {
			if c >= 0x20 && c < 0x7f {
				b.WriteByte(c)
			} else {
				b.WriteByte('.')
			}
		}
		b.WriteByte('\n')
		if _, err := io.WriteString(w, b.String()); err != nil {
			return err
		}
		b.Reset()
	}
	return nil
}
