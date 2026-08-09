package bench

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

// TUN — реальный TUN-fd. Прав не требует, если процесс сидит в собственном
// user+net namespace: `unshare -Urn` даёт CAP_NET_ADMIN внутри него.
type TUN struct {
	f    *os.File
	name string
	vnet bool
}

// virtioNetHdrLen — размер virtio_net_hdr перед каждым пакетом при IFF_VNET_HDR.
const virtioNetHdrLen = 10

// OpenTUN создаёт интерфейс. vnetHdr включает IFF_VNET_HDR и TUNSETOFFLOAD —
// единственный на Linux способ получить больше одного пакета за read(), то есть
// GSO, который §4 вынес за v1.
func OpenTUN(name string, vnetHdr bool) (*TUN, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun: %w", err)
	}

	ifr, err := unix.NewIfreq(name)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	flags := uint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if vnetHdr {
		flags |= unix.IFF_VNET_HDR
	}
	ifr.SetUint16(flags)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("TUNSETIFF: %w", err)
	}

	if vnetHdr {
		offloads := unix.TUN_F_CSUM | unix.TUN_F_TSO4 | unix.TUN_F_TSO6
		if err := unix.IoctlSetInt(fd, unix.TUNSETOFFLOAD, offloads|unix.TUN_F_USO4|unix.TUN_F_USO6); err != nil {
			// USO появился в ядре 6.2; без него остаётся TSO.
			if err := unix.IoctlSetInt(fd, unix.TUNSETOFFLOAD, offloads); err != nil {
				unix.Close(fd)
				return nil, fmt.Errorf("TUNSETOFFLOAD: %w", err)
			}
		}
	}

	return &TUN{f: os.NewFile(uintptr(fd), name), name: name, vnet: vnetHdr}, nil
}

func (t *TUN) Close() error { return t.f.Close() }

// Up поднимает интерфейс и вешает адрес.
func (t *TUN) Up(cidr string, mtu int) error {
	for _, args := range [][]string{
		{"ip", "link", "set", "dev", t.name, "mtu", fmt.Sprint(mtu)},
		{"ip", "addr", "add", cidr, "dev", t.name},
		{"ip", "link", "set", "dev", t.name, "up"},
	} {
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("%v: %v: %s", args, err, out)
		}
	}
	return nil
}

// TUNRead меряет путь «ядро → агент»: пакеты порождает UDP-отправитель внутри
// netns, агент забирает их read()-ом с дескриптора.
//
// senders > 1 нужен, чтобы отправитель не оказался узким местом: у него на
// пакет тоже приходится syscall.
func TUNRead(t *TUN, cfg Config, dst string, senders int) (Result, error) {
	var stop atomic.Bool
	payload := make([]byte, cfg.PktSize-28) // 20 IP + 8 UDP

	for i := 0; i < senders; i++ {
		go func() {
			c, err := net.Dial("udp", dst)
			if err != nil {
				return
			}
			defer c.Close()
			for !stop.Load() {
				if _, err := c.Write(payload); err != nil {
					return
				}
			}
		}()
	}

	buf := make([]byte, 65536)
	var pkts, bytes int64
	cpu0 := processCPU()
	start := wall.Now()
	deadline := start.Add(cfg.Duration)

	for wall.Now().Before(deadline) {
		n, err := t.f.Read(buf)
		if err != nil {
			stop.Store(true)
			return Result{}, err
		}
		pkts++
		bytes += int64(n)
	}
	elapsed := wall.Now().Sub(start)
	cpu := processCPU() - cpu0
	stop.Store(true)

	return Result{
		Name: "B1 linux tun read (ядро→агент)", OS: "linux", Batch: 1, PktSize: cfg.PktSize,
		Packets: pkts, Bytes: bytes, Wall: elapsed, CPU: cpu,
		Note: fmt.Sprintf("%d отправителей", senders),
	}, nil
}

// TUNWrite меряет путь «агент → ядро»: агент пишет готовые IP-пакеты в
// дескриптор, UDP-сокет в netns их вычитывает.
func TUNWrite(t *TUN, cfg Config, src, dst net.IP, port int) (Result, error) {
	sink, err := net.ListenPacket("udp", fmt.Sprintf("%s:%d", dst, port))
	if err != nil {
		return Result{}, err
	}
	defer sink.Close()

	var stop atomic.Bool
	go func() {
		b := make([]byte, 65536)
		for !stop.Load() {
			if _, _, err := sink.ReadFrom(b); err != nil {
				return
			}
		}
	}()

	pkt := udpPacket(src, dst, 12345, port, cfg.PktSize)
	var pkts, bytes int64
	cpu0 := processCPU()
	start := wall.Now()
	deadline := start.Add(cfg.Duration)

	for wall.Now().Before(deadline) {
		n, err := t.f.Write(pkt)
		if err != nil {
			stop.Store(true)
			return Result{}, err
		}
		pkts++
		bytes += int64(n)
	}
	elapsed := wall.Now().Sub(start)
	cpu := processCPU() - cpu0
	stop.Store(true)

	return Result{
		Name: "B1 linux tun write (агент→ядро)", OS: "linux", Batch: 1, PktSize: cfg.PktSize,
		Packets: pkts, Bytes: bytes, Wall: elapsed, CPU: cpu,
	}, nil
}

// TUNReadGSO — контрольный замер цены возврата GSO. Не гейт.
//
// Отправитель ставит UDP_SEGMENT, ядро отдаёт в TUN одну GSO-суперрамку, агент
// читает её одним read() и режет на сегменты. Разбор повторяет форму
// handleVirtioRead из wireguard-go (MIT), включая копирование каждого сегмента:
// без него замер показал бы цену чтения, а не цену GSO.
func TUNReadGSO(t *TUN, cfg Config, dst string, segSize, superSize int) (Result, error) {
	if !t.vnet {
		return Result{}, fmt.Errorf("TUNReadGSO требует IFF_VNET_HDR")
	}

	var stop atomic.Bool
	go func() {
		c, err := net.Dial("udp", dst)
		if err != nil {
			return
		}
		defer c.Close()
		rc, err := c.(*net.UDPConn).SyscallConn()
		if err != nil {
			return
		}
		var setErr error
		rc.Control(func(fd uintptr) {
			setErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_SEGMENT, segSize)
		})
		if setErr != nil {
			return
		}
		payload := make([]byte, superSize)
		for !stop.Load() {
			if _, err := c.Write(payload); err != nil {
				return
			}
		}
	}()

	in := make([]byte, virtioNetHdrLen+65535)
	out := make([][]byte, 128)
	for i := range out {
		out[i] = make([]byte, 65535)
	}

	var pkts, bytes, reads, superframes int64
	cpu0 := processCPU()
	start := wall.Now()
	deadline := start.Add(cfg.Duration)

	for wall.Now().Before(deadline) {
		n, err := t.f.Read(in)
		if err != nil {
			stop.Store(true)
			return Result{}, err
		}
		reads++
		segs, nbytes, gso, err := splitVirtio(in[:n], out)
		if err != nil {
			stop.Store(true)
			return Result{}, err
		}
		if gso {
			superframes++
		}
		pkts += int64(segs)
		bytes += int64(nbytes)
	}
	elapsed := wall.Now().Sub(start)
	cpu := processCPU() - cpu0
	stop.Store(true)

	note := fmt.Sprintf("сегмент %d Б, суперрамка %d Б; GSO-рамок %d из %d чтений",
		segSize, superSize, superframes, reads)
	if superframes == 0 {
		note = "ядро не отдало ни одной GSO-рамки; " + note
	}
	return Result{
		// PktSize — размер восстановленного пакета на проводе, а не полезной
		// нагрузки сегмента: так он сравним со строкой без GSO.
		Name: "B1 linux tun read + GSO (контроль)", OS: "linux", Batch: 1, PktSize: segSize + 28,
		Packets: pkts, Bytes: bytes, Wall: elapsed, CPU: cpu,
		PktPerR: float64(pkts) / float64(max(reads, 1)),
		Note:    note,
	}, nil
}

// splitVirtio режет прочитанное на пакеты. Возвращает число сегментов, сумму
// их длин и был ли кадр GSO-суперрамкой.
func splitVirtio(in []byte, out [][]byte) (segs, nbytes int, gso bool, err error) {
	if len(in) < virtioNetHdrLen {
		return 0, 0, false, fmt.Errorf("кадр короче virtio_net_hdr")
	}
	gsoType := in[1]
	gsoSize := int(binary.LittleEndian.Uint16(in[4:6]))
	body := in[virtioNetHdrLen:]

	if gsoType == unix.VIRTIO_NET_HDR_GSO_NONE {
		n := copy(out[0], body)
		return 1, n, false, nil
	}
	if gsoType != unix.VIRTIO_NET_HDR_GSO_UDP_L4 {
		// TSO без реконструкции TCP-заголовков нам для замера не нужен:
		// стоимость та же, а корректность считать сегменты сохраняется.
		return countOnly(body, gsoSize), len(body), true, nil
	}

	if len(body) < 20 {
		return 0, 0, false, fmt.Errorf("кадр короче IPv4-заголовка")
	}
	ihl := int(body[0]&0x0f) * 4
	if len(body) < ihl+8 || gsoSize <= 0 {
		return 0, 0, false, fmt.Errorf("некорректная UDP-суперрамка")
	}
	hdr := body[:ihl+8]
	payload := body[ihl+8:]

	for off := 0; off < len(payload); off += gsoSize {
		end := min(off+gsoSize, len(payload))
		if segs >= len(out) {
			return 0, 0, false, fmt.Errorf("сегментов больше %d", len(out))
		}
		seg := out[segs][:0]
		seg = append(seg, hdr...)
		seg = append(seg, payload[off:end]...)

		total := len(seg)
		binary.BigEndian.PutUint16(seg[2:4], uint16(total))             // IP total length
		binary.BigEndian.PutUint16(seg[ihl+4:ihl+6], uint16(total-ihl)) // UDP length
		seg[ihl+6], seg[ihl+7] = 0, 0                                   // контрольная сумма UDP не считается

		out[segs] = seg
		nbytes += total
		segs++
	}
	return segs, nbytes, true, nil
}

func countOnly(body []byte, gsoSize int) int {
	if gsoSize <= 0 {
		return 1
	}
	return (len(body) + gsoSize - 1) / gsoSize
}

// udpPacket собирает IPv4+UDP пакет ровно на total байт. Контрольная сумма UDP
// нулевая — для IPv4 это разрешено и ядро её не проверяет.
func udpPacket(src, dst net.IP, sport, dport, total int) []byte {
	p := make([]byte, total)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(total))
	p[8] = 64
	p[9] = unix.IPPROTO_UDP
	copy(p[12:16], src.To4())
	copy(p[16:20], dst.To4())
	binary.BigEndian.PutUint16(p[10:12], ipChecksum(p[:20]))

	binary.BigEndian.PutUint16(p[20:22], uint16(sport))
	binary.BigEndian.PutUint16(p[22:24], uint16(dport))
	binary.BigEndian.PutUint16(p[24:26], uint16(total-20))
	return p
}

func ipChecksum(h []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(h); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(h[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
