package pcapng

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

var (
	// ErrNotPcapng is returned when the input is recognizably a legacy
	// microsecond/nanosecond pcap file.
	ErrNotPcapng = errors.New("不是 pcapng：输入是旧式 .pcap 文件（microsecond magic）")
	// ErrNotPcapngNano is the nanosecond-magic variant.
	ErrNotPcapngNano = errors.New("不是 pcapng：输入是旧式 .pcap 文件（nanosecond magic）")
	// ErrNotRecognized is returned for arbitrary non-pcapng input.
	ErrNotRecognized = errors.New("不是 pcapng：文件头既不是 Section Header Block，也不是已知的 pcap magic")
)

var (
	leMagic = []byte{0x4d, 0x3c, 0x2b, 0x1a}
	beMagic = []byte{0x1a, 0x2b, 0x3c, 0x4d}
	pcapLE  = []byte{0xd4, 0xc3, 0xb2, 0xa1}
	pcapBE  = []byte{0xa1, 0xb2, 0xc3, 0xd4}
	pcapNS  = []byte{0x4d, 0x3c, 0xb2, 0xa1}
	pcapNSB = []byte{0xa1, 0xb2, 0x3c, 0x4d}
)

// Reader streams blocks from a pcapng file. At most one block payload is
// held in memory at a time (bounded by MaxBlockLen).
type Reader struct {
	r       *bufio.Reader
	order   binary.ByteOrder
	started bool
	n       int64 // bytes consumed
	blockNo int
}

// NewReader creates a streaming pcapng reader. Format detection is delayed
// until the first Next call so that tiny files get a clear error too.
func NewReader(r io.Reader) *Reader {
	br, ok := r.(*bufio.Reader)
	if !ok {
		br = bufio.NewReaderSize(r, 1<<20)
	}
	return &Reader{r: br}
}

// Next returns the next block. io.EOF is returned at a clean section/file
// end. Trailing garbage or truncated blocks produce descriptive errors.
func (rd *Reader) Next() (*Block, error) {
	hdr, err := rd.r.Peek(4)
	if err != nil {
		if errors.Is(err, io.EOF) {
			if len(hdr) == 0 && !rd.started {
				return nil, fmt.Errorf("%w（文件为空）", ErrNotRecognized)
			}
			if len(hdr) > 0 {
				return nil, fmt.Errorf("文件尾部有 %d 个游离字节：最后一个块之后的数据不是完整块头，文件可能被截断", len(hdr))
			}
			return nil, io.EOF
		}
		return nil, err
	}

	order := rd.order
	if !rd.started || bytesEqual(hdr, shbTypeBytes) {
		order, err = rd.detectOrder()
		if err != nil {
			return nil, err
		}
	}

	hdr8, err := rd.readExact(8)
	if err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, fmt.Errorf("块头被截断：文件偏移 %d 处只剩 %d 字节，需要 8 字节块头", rd.n, len(hdr))
		}
		return nil, err
	}
	btype := order.Uint32(hdr8[0:4])
	total := order.Uint32(hdr8[4:8])

	if total < 12 {
		return nil, fmt.Errorf("非法块长度 %d（块类型 %s，文件偏移 %d）：块长度至少 12 字节", total, blockName(btype), rd.n-8)
	}
	if total%4 != 0 {
		return nil, fmt.Errorf("非法块长度 %d（块类型 %s，文件偏移 %d）：长度必须是 4 的倍数", total, blockName(btype), rd.n-8)
	}
	if total > MaxBlockLen {
		return nil, fmt.Errorf("块长度 %d（块类型 %s，文件偏移 %d）超过上限 %d，文件很可能已损坏", total, blockName(btype), rd.n-8, MaxBlockLen)
	}

	bodyLen := int(total - 12)
	payload := make([]byte, bodyLen)
	if _, err := io.ReadFull(rd.r, payload); err != nil {
		return nil, fmt.Errorf("块 %s（文件偏移 %d）被截断：声明长度 %d 字节，但文件在此处结束，还差 %d 字节", blockName(btype), rd.n-8, total, total-8)
	}
	rd.n += int64(bodyLen)

	trail, err := rd.readExact(4)
	if err != nil {
		return nil, fmt.Errorf("块 %s（文件偏移 %d）被截断：缺少尾部块长度字段", blockName(btype), rd.n-8)
	}
	trailing := order.Uint32(trail[0:4])
	if trailing != total {
		return nil, fmt.Errorf("块 %s（文件偏移 %d）首尾长度不一致：头部 %d，尾部 %d", blockName(btype), rd.n-int64(total), total, trailing)
	}

	if btype == TypeSHB {
		if err := validateSHB(payload, order, rd.n-int64(total)); err != nil {
			return nil, err
		}
		rd.order = order
		rd.started = true
	} else if !rd.started {
		// Unreachable in practice: detectOrder already rejected this case.
		return nil, ErrNotRecognized
	}

	idx := rd.blockNo
	rd.blockNo++
	return &Block{
		Type:       btype,
		Total:      total,
		Payload:    payload,
		Offset:     rd.n - int64(total),
		Order:      order,
		BlockIndex: idx,
	}, nil
}

var shbTypeBytes = []byte{0x0a, 0x0d, 0x0d, 0x0a}

func (rd *Reader) detectOrder() (binary.ByteOrder, error) {
	head, err := rd.r.Peek(8)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(head) < 4 {
		return nil, fmt.Errorf("%w（文件只有 %d 字节）", ErrNotRecognized, len(head))
	}
	if !bytesEqual(head[0:4], shbTypeBytes) {
		switch {
		case bytesEqual(head[0:4], pcapLE) || bytesEqual(head[0:4], pcapBE):
			return nil, ErrNotPcapng
		case bytesEqual(head[0:4], pcapNS) || bytesEqual(head[0:4], pcapNSB):
			return nil, ErrNotPcapngNano
		default:
			return nil, ErrNotRecognized
		}
	}
	if len(head) < 8 {
		return nil, fmt.Errorf("SHB 块头被截断：文件只有 %d 字节，需要至少 8 字节", len(head))
	}
	// Byte Test Magic lives at SHB payload offset 0 (file offset 8).
	m, err := rd.r.Peek(12)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(m) < 12 {
		return nil, fmt.Errorf("SHB 被截断：无法读取字节序魔数，文件只有 %d 字节", len(m))
	}
	switch {
	case bytesEqual(m[8:12], leMagic):
		return binary.LittleEndian, nil
	case bytesEqual(m[8:12], beMagic):
		return binary.BigEndian, nil
	default:
		return nil, fmt.Errorf("不是 pcapng：SHB 字节序魔数为 % x（应为 % x 或 % x）", m[8:12], leMagic, beMagic)
	}
}

func validateSHB(payload []byte, o binary.ByteOrder, off int64) error {
	if len(payload) < 12 {
		return fmt.Errorf("SHB（文件偏移 %d）块体只有 %d 字节（至少需要 12）", off, len(payload))
	}
	var magic [4]byte
	copy(magic[:], payload[0:4])
	switch {
	case bytesEqual(magic[:], leMagic) && o == binary.LittleEndian:
	case bytesEqual(magic[:], beMagic) && o == binary.BigEndian:
	default:
		return fmt.Errorf("SHB（文件偏移 %d）字节序魔数 % x 与块长度编码不匹配", off, magic[:])
	}
	return nil
}

func (rd *Reader) readExact(n int) ([]byte, error) {
	buf := make([]byte, n)
	got, err := io.ReadFull(rd.r, buf)
	rd.n += int64(got)
	if err != nil {
		return buf[:got], err
	}
	return buf, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
