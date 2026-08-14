package sub

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// maxBody — потолок на тело подписки. Подписка — недоверенный вход, и без
// потолка провайдер (или тот, кто им притворился) кладёт агента одним ответом.
const maxBody = 8 << 20

// quotaHeader — §2, Group.quota_info. Заголовок отдаётся не всеми и в
// свободной форме; §7 (вопрос 3) ещё не решил, что с ним делать, поэтому он
// нигде не разбирается и кладётся в группу сырым.
const quotaHeader = "Subscription-UserInfo"

// Fetch забирает тело подписки и сырой заголовок квоты.
//
// Срок жизни запроса задаётся только ctx: своего таймаута здесь нет, потому
// что таймаут — это интервал, а интервалы в этом продукте не берутся из
// настоящего времени (§8.1).
func Fetch(ctx context.Context, rawURL string) (body []byte, quota string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, "", fmt.Errorf("sub: запрос подписки: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("sub: загрузка подписки: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("sub: подписка ответила %s", resp.Status)
	}
	body, err = io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, "", fmt.Errorf("sub: чтение подписки: %w", err)
	}
	if len(body) > maxBody {
		return nil, "", errors.New("sub: тело подписки больше допустимого")
	}
	return body, resp.Header.Get(quotaHeader), nil
}
