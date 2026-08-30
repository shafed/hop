package main

import (
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/ipc"
	"github.com/shafed/hop/internal/packet"
	"github.com/shafed/hop/internal/tunnel"
)

// agentDevice — устройство агента: PacketDevice (§3.2) плюс закрытие.
//
// Закрытие не входит в PacketDevice намеренно: связка устройством не владеет и
// закрывать его не должна. Но копия дескриптора, приехавшая по SCM_RIGHTS,
// принадлежит агенту, и кто-то обязан её отпустить — это делает транспорт,
// который её и получил.
type agentDevice interface {
	packet.PacketDevice
	close() error
}

// control — то, что транспорту нужно от управляющего соединения.
//
// Интерфейс, а не *ipc.Client, по тому же доводу, что у agent.Transport: с
// живым сокетом проверки W39 и W40 требовали бы поднятого hopd, то есть прав
// root, и уехали бы из L1 в L3. `*ipc.Client` удовлетворяет ему как есть.
type control interface {
	Start(p tunnel.Params) (ipc.Result, error)
	Attach(t tunnel.Token) (ipc.Result, error)
	Stop() error
	Heartbeat() error
	Detach(r tunnel.Reason) error
	Status() (tunnel.State, error)
}

// transport — реализация agent.Transport поверх управляющего соединения.
//
// Здесь же живут две вещи, которых связка знать не должна: превращение ответа
// сервиса в устройство (платформенный код) и heartbeat.
type transport struct {
	cl    control
	log   *slog.Logger
	store string // где лежит attach-token
	beat  time.Duration

	mu   sync.Mutex
	dev  agentDevice
	held bool

	lostOnce sync.Once
	lost     chan struct{}

	stop     chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

func newTransport(cl control, tokenFile string, beat time.Duration, log *slog.Logger) *transport {
	return &transport{
		cl: cl, log: log, store: tokenFile, beat: beat,
		lost: make(chan struct{}),
		stop: make(chan struct{}),
	}
}

// Acquire поднимает туннель и отдаёт устройство.
//
// Сначала реаттач по токену: если сервис в orphaned и токен от прошлого сеанса
// ещё жив, туннель забирается целиком — тот же интерфейс, тот же дескриптор
// (§6.2, T24). Только если не вышло — поднимается заново.
func (t *transport) Acquire(p tunnel.Params) (packet.PacketDevice, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.held {
		return nil, errors.New("транспорт: туннель уже взят")
	}

	res, err := t.acquire(p)
	if err != nil {
		return nil, err
	}

	dev, err := openDevice(res.FD, res.Device, p.MTU)
	if err != nil {
		// Туннель поднят, а устройства нет — оставить его так значило бы
		// маршруты в никуда, то есть чёрную дыру вместо отказа (§5.6).
		return nil, t.rollback(err, res.FD)
	}
	t.dev, t.held = dev, true

	// Heartbeat заводится вместе с туннелем, а не в main: его срыв и есть
	// признак смерти сервиса (Р41), и без туннеля следить не за чем.
	t.wg.Add(1)
	go t.heartbeat()

	// §6.14: токен не попадает в лог ни на debug — тип Token форматируется
	// заглушкой, и в аргументах его нет.
	t.log.Info("туннель получен", "device", res.Device)
	return dev, nil
}

func (t *transport) acquire(p tunnel.Params) (ipc.Result, error) {
	// attachErr и hadToken запоминаются не для лога: без них отказ ниже не
	// сможет сказать, ПОЧЕМУ туннель не забрали, — а без этого он не отказ по
	// §5.6, а сообщение о фазе.
	var attachErr error
	hadToken := false
	if tok, err := loadToken(t.store); err == nil {
		hadToken = true
		res, err := t.cl.Attach(tok)
		if err == nil {
			t.log.Info("реаттач по токену удался")
			return res, nil
		}
		attachErr = err
		t.log.Debug("реаттач не удался, поднимаем заново", "err", err)
	}

	res, err := t.cl.Start(p)
	if err != nil {
		return ipc.Result{}, t.explainStart(err, hadToken, attachErr)
	}
	if err := saveToken(t.store, res.Token); err != nil {
		// К этому месту сервис уже создал интерфейс и разложил маршруты.
		// Вернуть отсюда ошибку, не сняв туннель, значило бы оставить hopd с
		// поднятым туннелем без агента и без датаплейна — ту самую чёрную
		// дыру (§5.6), против которой весь этап и делался: откат Acquire по
		// отказу устройства стоит ниже и сюда уже не доходит.
		return ipc.Result{}, t.rollback(fmt.Errorf("токен не сохранён: %w", err), res.FD)
	}
	return res, nil
}

// explainStart заменяет отказ машины состояний отказом, который что-то значит
// пользователю (§5.6, W69).
//
// Отказ Start бывает по фазе, и одна из фаз — orphaned. Машина говорит про неё
// «операция недопустима в текущем состоянии: orphaned, ожидалось down»: фраза
// верна и бесполезна. Пользователь фазу не наблюдает (`hop status` показывает
// её только когда связки нет вовсе), снять её ему нечем, и ни одного слова о
// том, что делать, в ней нет. §5.6 требует от закрытия ровно обратного —
// назвать себя и оставить выход, а выход обязан существовать; вторую половину
// чинит runDown (W70).
//
// Заменяет, а не оборачивает: исходная фраза — это и есть дефект, и подклеенная
// в хвост она вернула бы жаргон туда, откуда его убирают. Для разбора она
// уезжает в debug.
//
// Все прочие отказы Start проходят насквозь: фаза up значит, что туннель уже
// поднят этим же агентом, и там сказать нечего сверх сказанного.
func (t *transport) explainStart(cause error, hadToken bool, attachErr error) error {
	st, err := t.cl.Status()
	if err != nil || st.Phase != tunnel.Orphaned {
		return cause
	}
	t.log.Debug("Start отказал в окне orphaned", "err", cause)

	dev := st.Device
	if dev == "" {
		dev = "интерфейс"
	}
	why := "attach-token того сеанса не найден (" + t.store + ")"
	if hadToken {
		// Токен есть, а сервис его не принял: это уже не потеря файла, и
		// назвать её потерей значило бы соврать. Сама причина приезжает
		// строкой — через IPC ошибки едут текстом, не типом.
		why = fmt.Sprintf("сохранённый attach-token (%s) сервис не принял: %v", t.store, attachErr)
	}
	return fmt.Errorf("туннель %s ещё жив, но осиротел%s, а забрать его нечем: %s. "+
		"Снять сейчас — `hop down`, после чего `hop up` поднимет новый; "+
		"либо подождать %s: сервис уберёт туннель сам (§6.2), и `hop up` пройдёт",
		dev, detachSuffix(st.DetachReason), why, leftText(st.OrphanLeft))
}

// detachSuffix — почему агента не стало, словами. Значения tunnel.Reason —
// имена рёбер §6.2, и показывать их пользователю значило бы менять один жаргон
// на другой.
func detachSuffix(r tunnel.Reason) string {
	switch r {
	case tunnel.ReasonClosed:
		return " (прежний агент оборвал соединение: kill -9 или падение)"
	case tunnel.ReasonHeartbeat:
		return " (прежний агент перестал отвечать)"
	case tunnel.ReasonRestart:
		return " (прежний агент ушёл на перезапуск)"
	default:
		return ""
	}
}

// leftText — остаток дедлайна для человека. Округление до секунды, потому что
// наносекунды в совете «подождите» — шум; остаток меньше секунды называется
// словами, иначе совет читается как «подождать 0 с».
func leftText(left time.Duration) string {
	if left < time.Second {
		return "меньше секунды"
	}
	return fmt.Sprintf("%d с", int(left.Round(time.Second).Seconds()))
}

// rollback снимает только что поднятый туннель и закрывает присланный
// дескриптор — общий хвост всех отказов между «сервис ответил» и «устройство
// готово».
//
// Порядок тот же, что в Release, и по той же причине: дескриптор отпускается
// до Stop, иначе сервис забирал бы интерфейс у ещё открытой копии.
//
// Ошибки отката не проглатываются, а едут вместе с исходной: молчаливый откат
// оставляет в логе причину, которой уже нет («токен не сохранён»), и прячет
// ту, что осталась на машине, — незакрытый туннель. Сцепка та же, что в
// internal/subscription/fetch.go: два %w, оба сохранены для errors.Is.
//
// Охраняют W45 (туннель снят) и W46 (дескриптор закрыт).
func (t *transport) rollback(cause error, fd int) error {
	if err := closeInboundFD(fd); err != nil {
		cause = fmt.Errorf("%w; дескриптор устройства не закрыт: %w", cause, err)
	}
	if err := t.cl.Stop(); err != nil {
		cause = fmt.Errorf("%w; туннель не снят: %w", cause, err)
	}
	return cause
}

// Release снимает туннель и закрывает агентскую копию дескриптора.
func (t *transport) Release() error {
	t.mu.Lock()
	dev, held := t.dev, t.held
	t.dev, t.held = nil, false
	t.mu.Unlock()

	if !held {
		return nil
	}
	// Устройство закрывается до Stop: иначе читатель связки, ещё не успевший
	// выйти, читал бы дескриптор, у которого сервис уже забрал интерфейс.
	if dev != nil {
		_ = dev.close()
	}
	return t.cl.Stop()
}

func (t *transport) Phase() (tunnel.Phase, error) {
	st, err := t.cl.Status()
	if err != nil {
		return "", err
	}
	return st.Phase, nil
}

// Lost закрывается, когда сервиса не стало (Р34).
func (t *transport) Lost() <-chan struct{} { return t.lost }

// heartbeat — и обязанность §6.2, и единственный детектор смерти сервиса
// (Р41). Второй механизм означал бы два ответа на один вопрос.
func (t *transport) heartbeat() {
	defer t.wg.Done()

	tk := clock.System{}.NewTicker(t.beat)
	defer tk.Stop()

	for {
		select {
		case <-t.stop:
			return
		case <-tk.C():
			if err := t.cl.Heartbeat(); err != nil {
				t.log.Error("heartbeat сорвался, считаем сервис пропавшим", "err", err)
				t.lostOnce.Do(func() { close(t.lost) })
				return
			}
		}
	}
}

// close останавливает heartbeat. Туннель при этом не снимается: плановый уход
// выражается Detach (§6.2), а не Stop, — иначе перезапуск агента ронял бы
// интерфейс, ради переживания которого orphaned и существует.
func (t *transport) close() {
	t.stopOnce.Do(func() { close(t.stop) })
	t.wg.Wait()
}

// detach — плановый уход: сервис узнаёт причину и показывает её в status, а
// окно отказа схлопывается до времени respawn (§6.2).
func (t *transport) detach() {
	t.mu.Lock()
	dev := t.dev
	t.dev, t.held = nil, false
	t.mu.Unlock()

	if dev != nil {
		_ = dev.close()
	}
	if err := t.cl.Detach(tunnel.ReasonRestart); err != nil {
		t.log.Debug("Detach", "err", err)
	}
}
