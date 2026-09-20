package pcapng

import (
	"math/big"
	"strings"
	"time"
)

// Timestamp assembles the EPB two 32-bit halves into a 64-bit tick count
// and formats it against the interface's if_tsresol option.
func Timestamp(p *Packet, iface *Interface) string {
	if !p.EPB {
		return "N/A"
	}
	ticks := uint64(p.TSHigh)<<32 | uint64(p.TSLow)
	res := byte(6)
	if iface != nil {
		res = iface.Resolution
	}

	base := byte(10)
	bits := res & 0x7f
	if res&0x80 != 0 {
		base = 2
	}

	if base == 10 {
		if bits == 0 {
			return time.Unix(0, int64(ticks)*int64(time.Second)).UTC().Format("2006-01-02T15:04:05Z")
		}
		if bits <= 9 {
			scale := pow10(int(9 - bits))
			return time.Unix(0, int64(ticks)*int64(scale)).UTC().Format(formatLayout(bits))
		}
		// Sub-nanosecond decimal resolutions are rare; render at nanosecond
		// precision using arbitrary-precision integer math.
		den := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(bits)), nil)
		return formatTickSeconds(new(big.Int).SetUint64(ticks), den)
	}

	// Base-2 resolution: seconds = ticks / 2^bits, render 9 frac digits.
	den := new(big.Int).Lsh(big.NewInt(1), uint(bits))
	return formatTickSeconds(new(big.Int).SetUint64(ticks), den)
}

func pow10(n int) int64 {
	v := int64(1)
	for i := 0; i < n; i++ {
		v *= 10
	}
	return v
}

func formatLayout(bits byte) string {
	if bits == 0 {
		return "2006-01-02T15:04:05Z"
	}
	return "2006-01-02T15:04:05." + strings.Repeat("0", int(bits)) + "Z"
}

var (
	bigNano    = big.NewInt(1e9)
	nanoLayout = "2006-01-02T15:04:05.000000000Z"
)

// formatTickSeconds formats ticks/den seconds in UTC with 9 fractional digits.
func formatTickSeconds(ticks, den *big.Int) string {
	sec := new(big.Int).Quo(ticks, den)
	rem := new(big.Int).Mod(ticks, den)
	nanos := new(big.Int).Mul(rem, bigNano)
	nanos.Quo(nanos, den)
	if ticks.Sign() < 0 && nanos.Sign() > 0 {
		sec.Sub(sec, big.NewInt(1))
		nanos.Sub(bigNano, nanos)
	}
	if !sec.IsInt64() || !nanos.IsInt64() {
		return "<timestamp out of range>"
	}
	return time.Unix(sec.Int64(), nanos.Int64()).UTC().Format(nanoLayout)
}
