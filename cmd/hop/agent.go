package main

import (
	"fmt"
	"sync"

	"github.com/shafed/hop/internal/cli"
	"github.com/shafed/hop/internal/events"
	"github.com/shafed/hop/internal/health"
	"github.com/shafed/hop/internal/ipc"
	"github.com/shafed/hop/internal/store"
	"github.com/shafed/hop/internal/supervisor"
	"github.com/shafed/hop/internal/tunnel"
)

// agentAPI — ответы агента клиентам (§3.3).
//
// Здесь и только здесь сходятся три источника состояния: сервис знает
// устройство и фазу orphaned (§3.1), супервизор — активный узел и причину
// переключения (§3.4), стор — имена узлов и те из них, что в выбор не попали
// (§6.11). Клиент видит один Status: два источника одной строки расходятся
// молча, и склейка обязана быть в одном месте (C9).
type agentAPI struct {
	sup *supervisor.Supervisor
	cl  *ipc.Client
	st  *store.Store

	mu   sync.Mutex
	auto bool
}

var _ events.Agent = (*agentAPI)(nil)

// newAgentAPI — автопереключение по умолчанию включено (§6.13).
func newAgentAPI(sup *supervisor.Supervisor, cl *ipc.Client, st *store.Store) *agentAPI {
	return &agentAPI{sup: sup, cl: cl, st: st, auto: true}
}

func (a *agentAPI) Status() events.Status {
	s := a.sup.Status()
	out := events.Status{
		Phase:      s.Phase,
		ActiveNode: s.ActiveNode,
		Auto:       a.autoOn(),
	}
	if s.LastSwitch.To != "" || s.LastSwitch.From != "" {
		sw := events.FromSwitch(s.LastSwitch)
		out.LastSwitch = &sw
	}
	if n, ok := a.st.Node(s.ActiveNode); ok {
		out.ActiveName = n.Name
	}
	for _, h := range a.sup.Nodes() {
		if h.NodeID == s.ActiveNode {
			out.RTTms = h.RTT.Milliseconds()
		}
	}

	// Сервис знает про туннель то, чего агент про себя знать не может: как ему
	// достаются пакеты и не осиротел ли туннель (§2). Недоступный сервис не
	// повод отказать в ответе — остальное состояние от этого не портится.
	if svc, err := a.cl.Status(); err == nil {
		out.Device = svc.Device
		if svc.Phase == tunnel.Orphaned || svc.Phase == tunnel.Down {
			out.Phase = svc.Phase
			out.DetachReason = svc.DetachReason
			out.OrphanLeftMS = svc.OrphanLeft.Milliseconds()
		}
	}
	return out
}

// Nodes — весь состав стора, а не только кандидаты: неподдержанный узел (§6.11)
// обязан быть виден в списке, иначе пользователь не поймёт, почему в подписке
// узлов больше, чем в выборе.
func (a *agentAPI) Nodes() []events.NodeInfo {
	live := make(map[string]health.NodeHealth, len(a.sup.Nodes()))
	for _, h := range a.sup.Nodes() {
		live[h.NodeID] = h
	}
	active := a.sup.Status().ActiveNode

	list := cli.StoreNodes(a.st)
	for i := range list {
		if h, ok := live[list[i].ID]; ok {
			list[i].State = h.State
			list[i].RTTms = h.RTT.Milliseconds()
			list[i].LastError = h.LastError
		}
		list[i].Active = list[i].ID == active
	}
	return list
}

// Pin — `hop up --node` (§С3): фиксация выключает автопереключение до
// `hop auto on`.
func (a *agentAPI) Pin(nodeID string) error {
	if err := a.sup.Pin(nodeID); err != nil {
		return err
	}
	a.setAuto(false)
	return nil
}

func (a *agentAPI) Auto(on bool) {
	a.sup.Auto(on)
	a.setAuto(on)
}

func (a *agentAPI) Bypass(on bool) { a.sup.Bypass(on) }

// Ping — `hop node ping`: форс-проверка (§6.6) и состояние узла после неё.
//
// Прогон синхронный и охватывает горячий ярус целиком (§6.5), а не один узел:
// расписание не умеет пробовать поштучно, и залп по всей подписке ради одной
// команды запрещён тем же §6.5. Узел из редкого яруса поэтому может ответить
// прежним состоянием.
func (a *agentAPI) Ping(nodeID string) (events.NodeInfo, error) {
	if _, ok := a.st.Node(nodeID); !ok {
		return events.NodeInfo{}, fmt.Errorf("узел %q не найден", nodeID)
	}
	a.sup.Force(health.TriggerRoute)
	for _, n := range a.Nodes() {
		if n.ID == nodeID {
			return n, nil
		}
	}
	return events.NodeInfo{}, fmt.Errorf("узел %q исчез из стора", nodeID)
}

func (a *agentAPI) autoOn() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.auto
}

func (a *agentAPI) setAuto(on bool) {
	a.mu.Lock()
	a.auto = on
	a.mu.Unlock()
}
