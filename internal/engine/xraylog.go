package engine

import (
	"fmt"
	"os"
	"sync"

	xlog "github.com/xtls/xray-core/common/log"
)

// Собственный лог Xray уводится со stdout.
//
// Замер: `hop probe --json` печатал в stdout строку
// «[Warning] common/errors: The feature WebSocket transport … is deprecated»
// перед JSON, то есть машинный вывод §5.9 переставал разбираться. Пишет её
// Xray своим глобальным логом (`common/log`), а не нашим кодом, и `loglevel:
// none` в конфиге инстанса её не гасит: предупреждение о конфиге появляется
// раньше, чем инстанс со своим логом.
//
// Stdout — машинный канал: в нём стоит ровно то, что напечатала команда
// (cmd/hop, emit). Всё остальное обязано идти в stderr, поэтому лог
// перенаправляется, а не глушится: диагностика чужой библиотеки полезна, но не
// в том канале, который разбирает автоматика.
//
// Место — здесь, потому что Xray принадлежит этому пакету (§3.4): гасить чужой
// глобальный лог из cmd/hop значило бы знать про Xray там, где про него знать
// не положено.
type xrayLog struct{}

func (xrayLog) Handle(msg xlog.Message) { fmt.Fprintln(os.Stderr, msg.String()) }

var xrayLogOnce sync.Once

// takeXrayLogOffStdout ставит наш обработчик глобального лога Xray.
//
// Once, а не init: смена глобального обработчика — действие владельца
// инстанса, а не побочный эффект импорта. Вызывается до сборки конфигурации,
// потому что предупреждения о конфигурации печатаются во время её разбора.
func takeXrayLogOffStdout() {
	xrayLogOnce.Do(func() { xlog.RegisterHandler(xrayLog{}) })
}
