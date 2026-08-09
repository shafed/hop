// Package bench — харнесс замера B1 (§8.6): пропускная способность границы
// «сервис → агент» синтетическим потоком 1400-байтных пакетов.
package bench

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/framing"
)

// wall — настоящие часы. Единственный законный потребитель: замер времени и
// есть смысл этого пакета.
var wall clock.Clock = clock.System{}

// Pipe — одно направление границы.
type Pipe struct {
	W io.WriteCloser
	R io.Reader
}

// Result — одно измерение.
type Result struct {
	Name    string        `json:"name"`
	OS      string        `json:"os"`
	Batch   int           `json:"batch"`
	PktSize int           `json:"pkt_size"`
	Packets int64         `json:"packets"`
	Bytes   int64         `json:"bytes"`
	Wall    time.Duration `json:"wall_ns"`
	CPU     time.Duration `json:"cpu_ns"`
	P50     time.Duration `json:"p50_ns,omitempty"`
	P99     time.Duration `json:"p99_ns,omitempty"`
	PktPerR float64       `json:"pkts_per_read,omitempty"`
	Note    string        `json:"note,omitempty"`
}

func (r Result) Mbps() float64 {
	if r.Wall == 0 {
		return 0
	}
	return float64(r.Bytes) * 8 / r.Wall.Seconds() / 1e6
}

func (r Result) PPS() float64 {
	if r.Wall == 0 {
		return 0
	}
	return float64(r.Packets) / r.Wall.Seconds()
}

// CPUPerGbit — секунд процессора на гигабит. Считает обе стороны границы:
// харнесс держит их в одном процессе.
func (r Result) CPUPerGbit() float64 {
	gbit := float64(r.Bytes) * 8 / 1e9
	if gbit == 0 {
		return 0
	}
	return r.CPU.Seconds() / gbit
}

// Config — параметры прогона.
type Config struct {
	PktSize  int
	Batch    int
	Duration time.Duration
	ReadBuf  int
	// RingCopy включает B1b: лишний memcpy из кольца Wintun перед записью в
	// трубу. Кольцо надо освободить, значит пакет надо скопировать.
	RingCopy bool
}

// ringBytes — порядок receive-кольца Wintun; берётся ради честного давления на
// кэш, а не ради ёмкости.
const ringBytes = 8 << 20

// Throughput гонит поток в одну сторону и возвращает достигнутую скорость.
func Throughput(name string, p Pipe, cfg Config) (Result, error) {
	src := newSource(cfg.PktSize, cfg.RingCopy)
	batch := make([][]byte, cfg.Batch)

	type readout struct {
		pkts, bytes int64
		err         error
	}
	done := make(chan readout, 1)

	go func() {
		r := framing.NewReader(p.R, cfg.ReadBuf)
		out := make([][]byte, cfg.Batch)
		var got readout
		for {
			n, err := r.ReadBatch(out)
			for _, pkt := range out[:n] {
				got.bytes += int64(len(pkt))
			}
			got.pkts += int64(n)
			if err != nil {
				if err != io.EOF {
					got.err = err
				}
				done <- got
				return
			}
		}
	}()

	w := framing.NewWriter(p.W, cfg.Batch*(cfg.PktSize+framing.HeaderLen)+64)
	cpu0 := processCPU()
	start := wall.Now()
	deadline := start.Add(cfg.Duration)

	for wall.Now().Before(deadline) {
		for i := range batch {
			batch[i] = src.next()
		}
		if err := w.WriteBatch(batch); err != nil {
			return Result{}, err
		}
	}
	if err := p.W.Close(); err != nil {
		return Result{}, err
	}

	got := <-done
	elapsed := wall.Now().Sub(start)
	cpu := processCPU() - cpu0

	return Result{
		Name: name, OS: osName(), Batch: cfg.Batch, PktSize: cfg.PktSize,
		Packets: got.pkts, Bytes: got.bytes, Wall: elapsed, CPU: cpu,
	}, got.err
}

// Latency меряет ping-pong через границу: пакет туда, тот же пакет обратно.
// Джиттер здесь важнее пропускной способности — приложения чувствуют его.
func Latency(name string, fwd, back Pipe, cfg Config, samples int) (Result, error) {
	// Эхо на дальней стороне.
	echoErr := make(chan error, 1)
	go func() {
		r := framing.NewReader(fwd.R, cfg.ReadBuf)
		w := framing.NewWriter(back.W, cfg.PktSize+framing.HeaderLen+64)
		out := make([][]byte, 1)
		for {
			n, err := r.ReadBatch(out)
			if n > 0 {
				if werr := w.WriteBatch(out[:n]); werr != nil {
					echoErr <- werr
					return
				}
			}
			if err != nil {
				echoErr <- nil
				return
			}
		}
	}()

	pkt := make([]byte, cfg.PktSize)
	one := [][]byte{pkt}
	w := framing.NewWriter(fwd.W, cfg.PktSize+framing.HeaderLen+64)
	r := framing.NewReader(back.R, cfg.ReadBuf)
	in := make([][]byte, 1)

	rtts := make([]time.Duration, 0, samples)
	cpu0 := processCPU()
	start := wall.Now()
	for i := 0; i < samples; i++ {
		t0 := hiresNow()
		if err := w.WriteBatch(one); err != nil {
			return Result{}, err
		}
		if _, err := r.ReadBatch(in); err != nil {
			return Result{}, err
		}
		rtts = append(rtts, hiresNow()-t0)
	}
	elapsed := wall.Now().Sub(start)
	cpu := processCPU() - cpu0
	fwd.W.Close()
	if err := <-echoErr; err != nil {
		return Result{}, err
	}

	sort.Slice(rtts, func(i, j int) bool { return rtts[i] < rtts[j] })
	return Result{
		Name: name, OS: osName(), Batch: 1, PktSize: cfg.PktSize,
		Packets: int64(samples), Bytes: int64(samples) * int64(cfg.PktSize),
		Wall: elapsed, CPU: cpu,
		P50: rtts[len(rtts)*50/100], P99: rtts[len(rtts)*99/100],
		Note: fmt.Sprintf("ping-pong, батч 1; шаг часов %v", hiresResolution()),
	}, nil
}

// source отдаёт пакеты. При RingCopy пакет сначала копируется из кольца —
// ReceivePacket отдаёт срез, который надо освободить до записи в трубу.
type source struct {
	ring    []byte
	off     int
	scratch []byte
	size    int
	copyOut bool
}

func newSource(size int, copyOut bool) *source {
	s := &source{size: size, copyOut: copyOut, scratch: make([]byte, size)}
	if copyOut {
		s.ring = make([]byte, ringBytes)
		for i := range s.ring {
			s.ring[i] = byte(i)
		}
	} else {
		for i := range s.scratch {
			s.scratch[i] = byte(i)
		}
	}
	return s
}

func (s *source) next() []byte {
	if !s.copyOut {
		return s.scratch
	}
	if s.off+s.size > len(s.ring) {
		s.off = 0
	}
	copy(s.scratch, s.ring[s.off:s.off+s.size])
	s.off += s.size
	return s.scratch
}

// Table печатает результаты человекочитаемой таблицей.
func Table(rs []Result) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%-34s %5s %6s %12s %10s %9s %8s %8s\n",
		"замер", "батч", "байт", "пак/с", "Мбит/с", "CPU с/Гбит", "p50", "p99")
	for _, r := range rs {
		p50, p99 := "-", "-"
		if r.P50 > 0 {
			p50 = r.P50.Round(100 * time.Nanosecond).String()
		}
		if r.P99 > 0 {
			p99 = r.P99.Round(100 * time.Nanosecond).String()
		}
		fmt.Fprintf(&b, "%-34s %5d %6d %12.0f %10.1f %9.3f %8s %8s\n",
			r.Name, r.Batch, r.PktSize, r.PPS(), r.Mbps(), r.CPUPerGbit(), p50, p99)
	}
	return b.String()
}

// JSON печатает результаты машиночитаемо — для CI-гейта.
func JSON(rs []Result) string {
	type row struct {
		Result
		Mbps float64 `json:"mbps"`
		PPS  float64 `json:"pps"`
	}
	rows := make([]row, len(rs))
	for i, r := range rs {
		rows[i] = row{r, r.Mbps(), r.PPS()}
	}
	out, _ := json.MarshalIndent(rows, "", "  ")
	return string(out)
}
