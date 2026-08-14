// Package probetarget — управляемый пробе-таргет стенда (§8.1): локальный
// HTTP-сервер, который по умолчанию отдаёт 204, как `generate_204`, а по
// команде теста переключается на 403, зависание или медленный ответ.
//
// Зачем настоящий сокет, а не подстановка на уровне интерфейса: §5.4 требует
// пережить блокировку тестового домена, а блокировка наблюдаема только как
// ответ чужого посредника (403) или как молчание (зависание). Проверять это на
// фейке значило бы проверять собственную догадку о том, как выглядит
// блокировка, а не поведение HTTP-клиента пробы — включая таймауты, отмену
// контекста и разбор кода ответа, то есть ровно то, что ломается в бою.
//
// Пакет намеренно **не импортирует testing**: им пользуются и тесты health, и
// будущий L2-стенд с настоящим Xray, и бенчмарки, а тестовые флаги в бинаре
// бенчмарка не нужны — та же причина, по которой fakenet живёт отдельно.
//
// Все методы безопасны для параллельного вызова: режим переключается на лету,
// пока проба уже идёт (T5, A30–A32 меняют поведение URL между раундами).
package probetarget

import (
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

// Mode — что таргет делает с очередным запросом.
type Mode uint8

const (
	// StatusNoContent — 204 без тела, как `generate_204`. Норма.
	StatusNoContent Mode = iota
	// StatusForbidden — 403. Имитация заблокированного тестового домена
	// (§5.4): посредник отвечает вместо сервера, соединение при этом
	// прекрасно устанавливается. Это сценарий T5/A30, и проба обязана считать
	// такой ответ неудачей.
	StatusForbidden
	// Hang — запрос принят, ответа нет. Имитация чёрной дыры: отличается от
	// 403 тем, что неудача видна только по таймауту, а не по коду. Разные
	// пути в коде клиента, поэтому и режимы разные (§8.1, там же про
	// `rst` против `blackhole`).
	Hang
	// Slow — 204 через задержку из SetDelay. Нужен для A31 (rtt берётся
	// минимальный из успешных) и A35 (rtt меряет путь трафика).
	Slow
)

func (m Mode) String() string {
	switch m {
	case StatusForbidden:
		return "403"
	case Hang:
		return "hang"
	case Slow:
		return "slow"
	default:
		return "204"
	}
}

// Path — путь, по которому таргет отвечает. Отвечает он на любой путь: тесту
// незачем знать, что именно запросила проба, а вот URL с осмысленным путём
// читается в отладке лучше, чем голый хост.
const Path = "/generate_204"

// Target — один управляемый пробе-таргет. Слушает 127.0.0.1 на случайном
// порту: стенд обязан работать без интернета и без прав (§8.1).
type Target struct {
	ln  net.Listener
	srv *http.Server
	url string

	// done закрывается в Close и вынимает зависшие обработчики. Без него
	// Close ждал бы Hang-запрос вечно, а тест — Close.
	done chan struct{}
	once sync.Once

	mu       sync.Mutex
	mode     Mode
	delay    time.Duration
	requests int
}

// New поднимает таргет и начинает обслуживать запросы.
//
// Ошибка слушателя не возвращается, а паникует: стенд без сокета — это не
// деградация теста, а невозможность его провести, и тихо продолжать здесь
// нечего. Полезной обработки у вызывающего всё равно нет.
func New() *Target {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic("probetarget: не удалось занять порт на 127.0.0.1: " + err.Error())
	}
	t := &Target{
		ln:   ln,
		url:  "http://" + ln.Addr().String() + Path,
		done: make(chan struct{}),
	}
	t.srv = &http.Server{
		Handler: http.HandlerFunc(t.serve),
		// Ни строчки в stderr: §6.14 запрещает утечку URL в логи, а рвущиеся
		// на Hang и Close соединения — штатный режим стенда, не событие.
		ErrorLog: log.New(io.Discard, "", 0),
	}
	go func() { _ = t.srv.Serve(ln) }()
	return t
}

// URL — адрес таргета для пробы.
func (t *Target) URL() string { return t.url }

// Addr — адрес слушателя. Нужен там, где проба ходит не по URL, а по паре
// хост:порт (диалер L2-стенда).
func (t *Target) Addr() string { return t.ln.Addr().String() }

// SetMode переключает режим. Действует со следующего запроса; запрос, уже
// принятый обработчиком, доигрывает по старому режиму — иначе тест смог бы
// поменять исход пробы задним числом и проверял бы не то.
func (t *Target) SetMode(m Mode) {
	t.mu.Lock()
	t.mode = m
	t.mu.Unlock()
}

// SetDelay задаёт задержку режима Slow.
func (t *Target) SetDelay(d time.Duration) {
	t.mu.Lock()
	t.delay = d
	t.mu.Unlock()
}

// SetSlow включает Slow с задержкой d одним действием. Отдельные SetDelay и
// SetMode оставляют окно, в котором таргет уже медленный, но задержка ещё
// старая; при переключении на лету это гонка в самом тесте.
func (t *Target) SetSlow(d time.Duration) {
	t.mu.Lock()
	t.mode, t.delay = Slow, d
	t.mu.Unlock()
}

// Requests — сколько запросов дошло до обработчика. Считается на входе, до
// задержки и до ответа: тесту нужно знать, что проба реально сходила по этому
// URL (A33), даже если ответа она не дождалась.
func (t *Target) Requests() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.requests
}

// Close останавливает таргет и рвёт все соединения, включая зависшие.
// Идемпотентен: тесты закрывают таргет и в t.Cleanup, и по ходу сценария.
func (t *Target) Close() {
	t.once.Do(func() {
		close(t.done)     // вынимаем Hang и Slow до закрытия сервера
		_ = t.srv.Close() // именно Close, а не Shutdown: Shutdown ждёт запросы
	})
}

func (t *Target) serve(w http.ResponseWriter, r *http.Request) {
	t.mu.Lock()
	t.requests++
	mode, delay := t.mode, t.delay
	t.mu.Unlock()

	switch mode {
	case StatusForbidden:
		w.WriteHeader(http.StatusForbidden)
	case Hang:
		t.wait(r, nil)
	case Slow:
		// Настоящее время, а не clock.Clock: задержка обязана быть видна
		// клиенту через сокет, а сокет живёт в настоящем времени. Фейковые
		// часы здесь измеряли бы сами себя.
		timer := time.NewTimer(delay) //hop:realtime
		defer timer.Stop()
		if t.wait(r, timer.C) {
			w.WriteHeader(http.StatusNoContent)
		}
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

// wait ждёт срабатывания until (nil — никогда). Возвращает true, если дождался
// и отвечать по-прежнему есть кому.
//
// Если раньше пришли отмена запроса или Close, обработчик обрывает соединение
// через http.ErrAbortHandler вместо возврата: возврат из обработчика без
// WriteHeader — это 200 OK, то есть зависший таргет на закрытии стенда отдал бы
// пробе успех. Такой ответ ничего не проверяет, зато прячет ошибку в тесте.
func (t *Target) wait(r *http.Request, until <-chan time.Time) bool {
	select {
	case <-until:
		return true
	case <-r.Context().Done():
	case <-t.done:
	}
	panic(http.ErrAbortHandler)
}
