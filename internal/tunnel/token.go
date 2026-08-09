package tunnel

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
)

// Token — attach-token из §3.1. Генерирует сервис, агент держит его только в
// памяти.
//
// Тип не строка намеренно: §6.14 запрещает секретам попадать в логи «ни на
// уровне debug», а самый частый способ туда попасть — `%v` по структуре,
// которая случайно оказалась в аргументах логгера. String и GoString отдают
// заглушку, поэтому ни один формат-глагол значение не выдаёт; настоящее
// значение достаётся только явным преобразованием string(t).
type Token string

// Redacted — то, что видно вместо токена в любом форматированном выводе.
const Redacted = "<attach-token>"

func (Token) String() string   { return Redacted }
func (Token) GoString() string { return Redacted }

// NewToken генерирует 128 бит из crypto/rand.
func NewToken() Token {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand на поддерживаемых ОС не отказывает; если отказал —
		// продолжать нельзя: токен станет предсказуемым.
		panic("tunnel: нет источника случайности: " + err.Error())
	}
	return Token(base64.RawURLEncoding.EncodeToString(b[:]))
}

// equal сравнивает токены за постоянное время.
func (t Token) equal(other Token) bool {
	return subtle.ConstantTimeCompare([]byte(t), []byte(other)) == 1
}
