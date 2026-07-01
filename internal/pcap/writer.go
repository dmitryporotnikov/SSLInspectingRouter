package pcap

import (
	"encoding/binary"
	"os"
	"sync"
	"time"
)

const (
	magicNumber  = 0xa1b2c3d4 // Libpcap File Format using Microsecond precision
	versionMajor = 2
	versionMinor = 4
	thisZone     = 0
	sigFigs      = 0
	snapLen      = 65535
	networkLL    = 1 // DLT_EN10MB (Ethernet)
)

type Writer struct {
	file  *os.File
	mu    sync.Mutex
	start time.Time
}

func NewWriter(filename string) (*Writer, error) {
	f, err := os.Create(filename)
	if err != nil {
		return nil, err
	}

	w := &Writer{
		file:  f,
		start: time.Now(),
	}

	if err := w.writeGlobalHeader(); err != nil {
		f.Close()
		return nil, err
	}

	return w, nil
}

func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.file.Close()
}

func (w *Writer) WritePacket(data []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.writePacket(data, time.Now())
}

func (w *Writer) writeGlobalHeader() error {
	// 24 bytes total
	buf := make([]byte, 24)
	binary.LittleEndian.PutUint32(buf[0:4], magicNumber)
	binary.LittleEndian.PutUint16(buf[4:6], versionMajor)
	binary.LittleEndian.PutUint16(buf[6:8], versionMinor)
	binary.LittleEndian.PutUint32(buf[8:12], uint32(thisZone))
	binary.LittleEndian.PutUint32(buf[12:16], uint32(sigFigs))
	binary.LittleEndian.PutUint32(buf[16:20], uint32(snapLen))
	binary.LittleEndian.PutUint32(buf[20:24], uint32(networkLL))

	_, err := w.file.Write(buf)
	return err
}

func (w *Writer) writePacket(data []byte, t time.Time) error {
	// Packet Header (16 bytes)
	// uint32 ts_sec
	// uint32 ts_usec
	// uint32 incl_len
	// uint32 orig_len

	header := make([]byte, 16)
	binary.LittleEndian.PutUint32(header[0:4], uint32(t.Unix()))
	binary.LittleEndian.PutUint32(header[4:8], uint32(t.Nanosecond()/1000))
	binary.LittleEndian.PutUint32(header[8:12], uint32(len(data)))
	binary.LittleEndian.PutUint32(header[12:16], uint32(len(data)))

	if _, err := w.file.Write(header); err != nil {
		return err
	}
	if _, err := w.file.Write(data); err != nil {
		return err
	}
	return nil
}
