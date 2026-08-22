package main

import (
	"github.com/shafed/hop/internal/health"
)

// probeURLs — тестовые адреса §5.4 (Р39).
//
// Три, а не один: §5.4 требует нескольких доменов ровно потому, что
// единственный тестовый домен может быть заблокирован, и тогда все узлы
// одновременно выглядят мёртвыми. Три — минимум, при котором блокировка двух
// ещё не хоронит подписку.
//
// HTTP, а не HTTPS: `generate_204` — стандартная проверка связности, и TLS
// добавил бы к замеру рукопожатие, которого §6.7 не просит. Редиректы не
// выполняются (см. HTTPTarget): пройти по редиректу значит померить другой хост.
var probeURLs = []string{
	"http://cp.cloudflare.com/generate_204",
	"http://www.gstatic.com/generate_204",
	"http://connectivitycheck.gstatic.com/generate_204",
}

// newProber собирает пробер §5.4 поверх дозвона через outbound узла (§6.7).
//
// dial приходит аргументом и вызывается лениво: диалер живёт в связке, а связку
// нельзя собрать раньше живости, которой нужен этот пробер. Замыкание разрывает
// круг, не заводя ни второго владельца движка, ни поля, которое кто-то забудет
// проставить.
func newProber(dial health.DialFunc) *health.MultiProber {
	targets := make([]health.Target, 0, len(probeURLs))
	for _, u := range probeURLs {
		targets = append(targets, &health.HTTPTarget{URL: u, Dial: dial})
	}
	return &health.MultiProber{Targets: targets}
}
