//go:build linux || darwin

package bench

import "time" //hop:realtime

// hiresEpoch несёт монотонное чтение; hiresNow считает от него разницу, а не
// абсолютное время, поэтому подводка стенных часов на замер не влияет.
var hiresEpoch = wall.Now()

// hiresNow — монотонное время наносекундного разрешения.
func hiresNow() time.Duration { return wall.Now().Sub(hiresEpoch) }
