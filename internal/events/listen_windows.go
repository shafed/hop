//go:build windows

package events

import "net"

// listen — Windows: umask и группы там нет, границу выражает ACL, и это часть
// платформенного долга §7.2 вместе с самой трубой. gid не применим.
func listen(path string, _ int) (net.Listener, error) { return net.Listen("unix", path) }
