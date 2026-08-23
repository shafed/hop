package resolver

import (
	"context"
	"errors"

	"github.com/shafed/hop/internal/dnsmsg"
	"github.com/shafed/hop/internal/phase"
	"github.com/shafed/hop/internal/policy"
)

// errFailClose — отказ по фазе трафика. Спина превращает его в SERVFAIL и в
// кэш при этом не заглядывает вовсе.
var errFailClose = errors.New("resolver: живых узлов нет, резолв закрыт (§5.7б)")

// gate — что делать с запросом в текущей фазе трафика.
//
// §5.7(б) требует «нет живых узлов — нет резолва», но порядок вердиктов §3.4
// ставит hijack-dns первым: до пункта «reject» DNS-поток не доходит никогда, и
// fail-close к нему не применяется вообще. Значит §5.7(б) обязан быть выполнен
// здесь, иначе он не выполнен нигде (Р15).
func (r *Resolver) gate(ctx context.Context, q dnsmsg.Msg) (route, error) {
	switch r.cfg.Phase() {
	case phase.Bypass:
		// C8: в фазе bypass перехваченный DNS идёт мимо узлов. Маршрут решается
		// здесь один раз на запрос: фаза может смениться посреди резолва, и
		// попытка с её повтором обязаны идти одной дорогой.
		return routeDirect, nil

	case phase.Failing:
		if !policy.DNSFailClose.On() {
			// dns_failclose выключена — резолвер отвечает и без живых узлов.
			// Приложение получает адреса и виснет на connect, то есть молчание,
			// запрещённое §5.6, сдвигается на шаг дальше. Краснит D9–D11, D17.
			return routeNode, nil
		}
		return 0, errFailClose

	case phase.Waiting:
		return r.hold(ctx, q)

	default:
		return routeNode, nil
	}
}

// hold — удержание запроса в стартовом окне §5.6 (Р16).
//
// Ждёт появления живого узла, но не дольше WaitingHold. Дольше не выигрывает
// ничего: типовой стаб ОС ждёт ответа 5 секунд и затем спрашивает следующий
// сервер — тоже нас, — то есть удержание сверх четырёх секунд отнимает у него
// право на собственный ретрай и держит наши горутины сверх потолка У5.
//
// Ждёт на сигнале, а не опросом по таймеру: фаза приходит функцией, и опрос
// означал бы либо задержку в размер шага, либо сотни тиков на каждое
// удержание. Сигнал даёт связка через PhaseChanged — она и так зовёт
// refreshPhase на каждом переходе.
func (r *Resolver) hold(ctx context.Context, _ dnsmsg.Msg) (route, error) {
	if !policy.DNSWaitingHold.On() {
		// dns_waiting_hold выключена — SERVFAIL сразу, без удержания.
		// Приложение, стартовавшее вместе с агентом, получает отказ там, где
		// через секунду всё работало. Краснит D12, D13.
		return 0, errFailClose
	}

	r.cnt.held.Add(1)
	defer r.cnt.held.Add(-1)

	limit := r.clk.After(WaitingHold)
	for {
		r.mu.Lock()
		wake := r.wake
		r.mu.Unlock()

		select {
		case <-wake:
			switch r.cfg.Phase() {
			case phase.Waiting:
				// Фаза сменилась, но всё ещё стартовое окно: ждём дальше по
				// тому же общему сроку, а не заводим новый.
				continue
			case phase.Failing:
				return 0, errFailClose
			case phase.Bypass:
				return routeDirect, nil
			default:
				return routeNode, nil
			}
		case <-limit:
			return 0, errFailClose
		case <-ctx.Done():
			return 0, errFailClose
		case <-r.done:
			return 0, errFailClose
		}
	}
}

// PhaseChanged — связка сообщает, что фаза трафика могла смениться.
//
// Делает две вещи: будит удержанные запросы и ловит край bypass. Заметить край
// сам резолвер не может — фаза опрашивается функцией, — но решение о том, что
// считать краем и что при этом сбросить, остаётся здесь. Связка говорит
// «посмотри», а не «сбрось»: §5.7 требует, чтобы сброс делал резолвер.
//
// Р25: вход в bypass и выход из него сбрасывают кэш так же, как смена узла.
// Причина та же, что в §5.7(в): адрес, полученный напрямую, указывает на CDN
// нашего настоящего региона, и после возврата в туннель трафик пойдёт туда же
// — то есть выключение bypass не вернуло бы защиту полностью.
func (r *Resolver) PhaseChanged() {
	now := r.cfg.Phase() == phase.Bypass

	r.mu.Lock()
	edge := now != r.inBypass
	r.inBypass = now
	close(r.wake)
	r.wake = make(chan struct{})
	r.mu.Unlock()

	if !edge {
		return
	}
	if !policy.DNSCacheFlushOnSwitch.On() {
		// Тот же флаг, что снимает сброс по подписке, снимает и этот. Р25
		// говорит, что край bypass сбрасывает кэш «так же, как смена узла», —
		// значит и выключаться они обязаны вместе: флаг про то, сбрасываем ли
		// мы кэш при смене того, через что резолвим, а не про то, какой
		// именно провод об этой смене сообщил. Краснит D20.
		return
	}
	r.flush()
}

// watchSwitches — подписка §5.7: кэш сбрасывает сам резолвер.
//
// Связка только соединяет провода. Разница не косметическая: при вызове
// Flush() из обработчика переключения забытый вызов в новой ветке кода —
// молчаливая регрессия, которую флаг отключения политики не ловит, потому что
// ловить нечего. Подписка же снимается флагом целиком.
func (r *Resolver) watchSwitches() {
	defer r.wg.Done()
	for {
		select {
		case <-r.done:
			return
		case _, ok := <-r.cfg.Events:
			if !ok {
				return
			}
			if policy.DNSCacheFlushOnSwitch.On() {
				r.flush()
			}
			// dns_cache_flush_on_switch выключена — подписка есть, а сброса
			// нет: после переключения трафик уходит в CDN чужого региона по
			// адресу, добытому через прежний узел. Краснит T14, D19, D20.
			if r.cfg.Acked != nil {
				r.cfg.Acked()
			}
		}
	}
}

// flush выкидывает кэш целиком и двигает Generation.
//
// Наблюдаемость счётчиком, а не последствием: без Generation проверка «после
// переключения адрес другой» зелена и в реализации, где кэша нет вовсе, — то
// есть не охраняет ничего (D19).
func (r *Resolver) flush() {
	r.cache.reset()
	r.cnt.generation.Add(1)
}

// switched — случилось ли переключение узла, пока шёл этот запрос.
//
// Смотрит на Generation, а не на отдельный счётчик переключений: сброс кэша и
// есть наблюдаемое следствие переключения, и заводить второй источник правды о
// том же событии значило бы разрешить им разъехаться.
func (r *Resolver) switched(gen uint64) bool {
	if !policy.DNSSwitchRetry.On() {
		// dns_switch_retry выключена — запрос, застигнутый переключением,
		// отдаёт SERVFAIL. Краснит D16.
		return false
	}
	return r.cnt.generation.Load() != gen
}
