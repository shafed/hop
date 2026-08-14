package events

import (
	"encoding/json"
	"errors"
	"net"
)

// Client — тонкий клиент агента (§3.3): вся логика в агенте, здесь только
// вызовы.
//
// Одно соединение — одна команда. Для подписки соединение после Follow занято
// потоком событий и другие команды по нему не идут.
type Client struct {
	c   net.Conn
	dec *json.Decoder
	enc *json.Encoder
}

// Dial подключается к сокету агента.
func Dial(path string) (*Client, error) {
	c, err := net.Dial("unix", path)
	if err != nil {
		return nil, err
	}
	return &Client{c: c, dec: json.NewDecoder(c), enc: json.NewEncoder(c)}, nil
}

// Close закрывает соединение. Он же способ прервать Follow: чтение просыпается
// только закрытием.
func (c *Client) Close() error { return c.c.Close() }

func (c *Client) Status() (Status, error) {
	resp, err := c.do(Request{Cmd: CmdStatus})
	if err != nil {
		return Status{}, err
	}
	if resp.Status == nil {
		return Status{}, errors.New("events: пустой status")
	}
	return *resp.Status, nil
}

func (c *Client) Nodes() ([]NodeInfo, error) {
	resp, err := c.do(Request{Cmd: CmdNodes})
	return resp.Nodes, err
}

func (c *Client) Pin(nodeID string) error {
	_, err := c.do(Request{Cmd: CmdPin, Node: nodeID})
	return err
}

func (c *Client) Auto(on bool) error {
	_, err := c.do(Request{Cmd: CmdAuto, On: on})
	return err
}

func (c *Client) Bypass(on bool) error {
	_, err := c.do(Request{Cmd: CmdBypass, On: on})
	return err
}

func (c *Client) Ping(nodeID string) (NodeInfo, error) {
	resp, err := c.do(Request{Cmd: CmdPing, Node: nodeID})
	if err != nil {
		return NodeInfo{}, err
	}
	if resp.Node == nil {
		return NodeInfo{}, errors.New("events: пустой ответ на ping")
	}
	return *resp.Node, nil
}

// Follow подписывается на события. Дальше соединение читается только Next.
func (c *Client) Follow() error { return c.enc.Encode(Request{Cmd: CmdEvents}) }

// Next ждёт следующее событие. Возвращает ошибку, когда агент ушёл или
// соединение закрыли.
func (c *Client) Next() (Event, error) {
	var resp Response
	if err := c.dec.Decode(&resp); err != nil {
		return Event{}, err
	}
	if resp.Error != "" {
		return Event{}, errors.New(resp.Error)
	}
	if resp.Event == nil {
		return Event{}, errors.New("events: пустое событие")
	}
	return *resp.Event, nil
}

func (c *Client) do(req Request) (Response, error) {
	if err := c.enc.Encode(req); err != nil {
		return Response{}, err
	}
	var resp Response
	if err := c.dec.Decode(&resp); err != nil {
		return Response{}, err
	}
	if resp.Error != "" {
		return resp, errors.New(resp.Error)
	}
	return resp, nil
}
