// Путь скачивания и обновления подписки (§5.8, Р7). Регистр проверок —
// docs/verification-store.md §5.2 (S14, S15) и §4 (числа).
//
// Живёт в subscription, а не в store, по двум причинам сразу: §3.4 числит за
// подпиской «загрузку, парсинг ссылок, diff-слияние», а импорт store →
// subscription был бы циклом (docs/verification-store.md §2). Обратное
// направление — subscription → store — законно, поэтому связать скачивание,
// разбор, слияние и запись можно только здесь.
//
// Правило Р7 целиком: тело читается в память до конца, разбирается целиком, и
// только полностью разобранный непустой результат идёт в слияние. Цена ошибки
// несимметрична — лишний отказ обновления стоит строки в выводе, лишнее
// удаление стоит всей истории проб.

package subscription

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time" //hop:realtime — только константы длительности, обращений к часам здесь нет

	"github.com/shafed/hop/internal/clock"
	"github.com/shafed/hop/internal/store"
)

const (
	// MaxBodySize — потолок тела подписки, 8 МиБ (§4 регистра). Тело читается
	// целиком в память, значит потолок обязателен: без него подписка — это
	// сколько угодно памяти по чужому решению.
	MaxBodySize = 8 << 20

	// DownloadTimeout — 30 с на всё скачивание (§4 регистра).
	DownloadTimeout = 30 * time.Second

	// quotaHeader — сырой заголовок остатка квоты (§2). Хранится как есть и не
	// разбирается (§7, п. 3).
	quotaHeader = "Subscription-Userinfo"
)

// Ошибки пути скачивания. Именованные, а не текст: вызывающему нужно отличать
// «провайдер отдал не то» от «сеть не дошла», и на этом различии стоят S14 и
// S15.
var (
	// ErrEmptySubscription — разбор дал ноль узлов (Р7, S14).
	ErrEmptySubscription = errors.New("subscription: подписка разобралась в ноль узлов")
	// ErrTruncated — тело кончилось раньше обещанного (Р7, S15).
	ErrTruncated = errors.New("subscription: тело подписки оборвано")
	// ErrTooLarge — тело больше потолка §4.
	ErrTooLarge = errors.New("subscription: тело подписки больше потолка")
	// ErrTimeout — не уложились в DownloadTimeout.
	ErrTimeout = errors.New("subscription: подписка не скачалась за отведённое время")
)

// Doer — то немногое, что путь скачивания хочет от HTTP-клиента. *http.Client
// его удовлетворяет; проверки подставляют свой, потому что настоящей сети в
// тестах быть не должно.
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Body — тело подписки и то, что пришло вместе с ним.
type Body struct {
	// Data — тело целиком. Целиком, а не потоком: разбор всё равно смотрит на
	// вход как на единое, а поток пришлось бы обрывать посередине — ровно то,
	// что Р7 запрещает применять.
	Data []byte
	// QuotaInfo — сырой заголовок Subscription-UserInfo, если пришёл (§2).
	QuotaInfo string
}

// Downloader — скачивание тела подписки.
//
// Часы отдельно от клиента: таймаут §4 отсчитывается по clock.Clock, иначе
// проверка на него стоила бы тридцати секунд настоящего времени (§8.1). У
// сокета под нами свои дедлайны, но их ставит http.Client, а не мы.
type Downloader struct {
	doer    Doer
	clk     clock.Clock
	max     int64
	timeout time.Duration
}

// NewDownloader собирает загрузчик. Пустой doer означает http.DefaultClient,
// пустые часы — системные: и то и другое — боевые значения по умолчанию.
func NewDownloader(doer Doer, clk clock.Clock) *Downloader {
	if doer == nil {
		doer = http.DefaultClient
	}
	if clk == nil {
		clk = clock.System{}
	}
	return &Downloader{doer: doer, clk: clk, max: MaxBodySize, timeout: DownloadTimeout}
}

// Get скачивает тело подписки целиком.
//
// Отказ на любом шаге — это отказ обновления, а не половина подписки: до
// слияния такое тело не доходит.
func (d *Downloader) Get(ctx context.Context, url string) (Body, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Таймаут по часам стора, а не context.WithTimeout: тот берёт настоящее
	// время, и фейковые часы его не двигают. Канал создаётся здесь, а не
	// внутри горутины, чтобы к моменту запроса ожидание уже стояло на часах.
	deadline := d.clk.After(d.timeout)
	done := make(chan struct{})
	defer close(done)
	expired := make(chan struct{})
	go func() {
		select {
		case <-deadline:
			close(expired)
			cancel()
		case <-done:
		}
	}()
	timedOut := func() bool {
		select {
		case <-expired:
			return true
		default:
			return false
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Body{}, fmt.Errorf("subscription: не собрать запрос к подписке: %w", err)
	}
	resp, err := d.doer.Do(req)
	if err != nil {
		if timedOut() {
			return Body{}, fmt.Errorf("%w (%s)", ErrTimeout, d.timeout)
		}
		return Body{}, fmt.Errorf("subscription: не скачать подписку: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Body{}, fmt.Errorf("subscription: подписка ответила %q, а не успехом", resp.Status)
	}

	// LimitReader на потолок плюс байт: лишний байт отличает «ровно потолок» от
	// «больше потолка», и памяти на чтение уходит не больше потолка в любом
	// случае.
	data, err := io.ReadAll(io.LimitReader(resp.Body, d.max+1))
	if err != nil {
		if timedOut() {
			return Body{}, fmt.Errorf("%w (%s)", ErrTimeout, d.timeout)
		}
		// Чтение оборвалось на середине — отказ (Р7, S15). Оборванное тело
		// неотличимо от подписки, из которой провайдер убрал половину узлов, а
		// diff-слияние удалило бы их вместе с историей проб.
		return Body{}, fmt.Errorf("%w: чтение прервалось на %d байте: %w", ErrTruncated, len(data), err)
	}
	if int64(len(data)) > d.max {
		return Body{}, fmt.Errorf("%w %d байт", ErrTooLarge, d.max)
	}
	// Второй способ увидеть обрыв: тела пришло меньше обещанного заголовком.
	// Без него аккуратно обрезанное тело выглядит как честное и короткое.
	if resp.ContentLength >= 0 && int64(len(data)) != resp.ContentLength {
		return Body{}, fmt.Errorf("%w: пришло %d байт из обещанных %d", ErrTruncated, len(data), resp.ContentLength)
	}

	return Body{Data: data, QuotaInfo: resp.Header.Get(quotaHeader)}, nil
}

// Updater — обновление подписки целиком: скачать, разобрать, слить, записать.
type Updater struct {
	// Store — куда ложится результат. Обязателен.
	Store *store.Store
	// Downloader — чем берётся тело. Обязателен.
	Downloader *Downloader
	// NewID — генератор id новых узлов. Приходит снаружи по той же причине,
	// что и у Diff: со случайностью внутри проверки тождества узла зависели бы
	// от неё, а не от ключа §6.16. Пустой означает NewID.
	NewID func() string
}

// Result — что дало обновление подписки.
type Result struct {
	// Merged — состав, решённый слиянием: Added, Kept, Removed по id и сводка
	// импорта по причинам (§1/С2).
	Merged store.Merged
	// Format — какая ступень каскада §6.12 взяла тело.
	Format Format
	// QuotaInfo — сырой заголовок Subscription-UserInfo, если пришёл. Пока
	// только возвращается: записать его в группу этой дорогой нельзя — Merged
	// метаданных подписки не несёт.
	QuotaInfo string
}

// Update обновляет группу groupID из подписки по ссылке url (§5.8).
//
// Правило Р7 держится порядком шагов: скачать целиком → разобрать целиком →
// убедиться, что узлы есть → и только теперь слить и записать. Любой отказ до
// последнего шага оставляет группу ровно такой, какой она была: слияние даже не
// начиналось.
func (u *Updater) Update(ctx context.Context, groupID, url string) (Result, error) {
	switch {
	case u.Store == nil:
		return Result{}, errors.New("subscription: обновление без стора")
	case u.Downloader == nil:
		return Result{}, errors.New("subscription: обновление без загрузчика")
	case groupID == store.ManualGroupID:
		// Р10: manual — не подписка, обновлять нечего. Отказ, а не молчание:
		// сюда можно попасть только ошибкой вызывающего.
		return Result{}, fmt.Errorf("subscription: группа %q не подписка, обновлять нечего", store.ManualGroupID)
	}
	newID := u.NewID
	if newID == nil {
		newID = NewID
	}

	body, err := u.Downloader.Get(ctx, url)
	if err != nil {
		return Result{}, err
	}

	p, err := Parse(body.Data)
	if err != nil {
		return Result{}, err
	}
	if len(p.Nodes) == 0 {
		// Ноль узлов — отказ (Р7, S14). Разобранное в ноль тело неотличимо от
		// подписки, которую провайдер опустошил по ошибке, и применить его
		// значило бы удалить группу вместе с историей проб.
		return Result{Format: p.Format}, fmt.Errorf("%w (формат %s, негодных строк %d); группа оставлена прежней",
			ErrEmptySubscription, p.Format, len(p.Unsupported))
	}

	m := Diff(groupID, u.Store.Nodes(groupID), p, newID)
	if err := u.Store.Apply(groupID, m); err != nil {
		return Result{}, err
	}
	return Result{Merged: m, Format: p.Format, QuotaInfo: body.QuotaInfo}, nil
}

// NewID — идентификатор нового узла по умолчанию: 128 бит из crypto/rand.
// Случайный, а не порядковый: порядковый пришлось бы хранить и восстанавливать,
// и после порчи стора он начал бы выдавать id, уже занятые живостью.
func NewID() string {
	var b [16]byte
	// crypto/rand.Read ошибки не возвращает: источник энтропии либо есть, либо
	// программа до этой строки не дошла бы.
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
