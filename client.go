package irc

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
)

type Message struct {
	Raw     string
	Prefix  string
	Command string
	Params  []string
}

func pad(in []string, n int) []string {
	if len(in) == n {
		return in
	}
	out := make([]string, n)
	copy(out, in)
	return out
}

func Parse(s string) *Message {
	m := &Message{Raw: s}

	if s[0] == ':' {
		parts := pad(strings.SplitN(s, " ", 3), 3)
		m.Prefix = parts[0][1:]
		m.Command = parts[1]
		m.Params = parseParams(parts[2])
		return m
	}

	parts := pad(strings.SplitN(s, " ", 2), 2)
	m.Command = parts[0]
	m.Params = parseParams(parts[1])
	return m
}

func parseParams(params string) []string {
	if len(params) == 0 {
		return nil
	}

	if params[0] == ':' {
		if len(params) == 1 {
			return []string{""}
		}
		return []string{strings.TrimRight(params[1:], " ")}
	}

	idx := strings.Index(params, " :")
	if idx == -1 {
		return strings.Split(params, " ")
	}

	left, right := params[:idx], strings.TrimRight(params[idx+2:], " ")
	var out []string
	if len(left) > 0 {
		out = strings.Split(left, " ")
	}
	if idx < len(params) {
		out = append(out, right)
	}
	return out
}

func (m *Message) String() string {
	return m.Raw
}

func (m *Message) IsNumeric() bool {
	if len(m.Command) != 3 {
		return false
	}
	s := m.Command
	return s[0] >= '0' && s[0] <= '9' &&
		s[1] >= '0' && s[1] <= '9' &&
		s[2] >= '0' && s[2] <= '9'
}

func (m *Message) IsError() bool {
	return m.IsNumeric() && m.Command[0] >= '4' && m.Command[0] <= '5'
}

func (m *Message) IsCTCP() bool {
	if len(m.Params) == 0 {
		return false
	}

	s := m.Params[len(m.Params)-1]
	if len(s) < 2 {
		return false
	}

	return s[0] == 1 && s[len(s)-1] == 1
}

func (m *Message) CTCP() (*CTCPMessage, error) {
	if !m.IsCTCP() {
		return nil, errors.New("not a CTCP message")
	}
	return ParseCTCP(m.Params[len(m.Params)-1])
}

type CTCPMessage struct {
	Command string
	Params  []string
}

func ParseCTCP(s string) (*CTCPMessage, error) {
	if len(s) < 2 {
		return nil, errors.New("not a CTCP message")
	}
	m := &CTCPMessage{}
	s = s[1 : len(s)-1]
	parts := strings.Split(s, " ")
	m.Command = parts[0]
	if len(parts) > 1 {
		m.Params = parts[1:]
	}
	return m, nil
}

type Handler interface {
	Process(*Client, *Message)
}

type HandlerFunc func(*Client, *Message)

func (f HandlerFunc) Process(c *Client, m *Message) {
	f(c, m)
}

type Mux struct {
	mu *sync.RWMutex
	m  map[string][]Handler
}

func NewMux() *Mux {
	mux := &Mux{new(sync.RWMutex), make(map[string][]Handler)}
	mux.HandleFunc("PING", func(c *Client, m *Message) {
		c.Send(fmt.Sprintf("PONG %s", m.Params[0]))
	})
	return mux
}

func (mux *Mux) Handle(command string, handler Handler) {
	mux.mu.Lock()
	defer mux.mu.Unlock()
	mux.m[command] = append(mux.m[command], handler)
}

func (mux *Mux) HandleFunc(command string, handler func(*Client, *Message)) {
	mux.Handle(command, HandlerFunc(handler))
}

func (mux *Mux) Handler(m *Message) (hs []Handler) {
	mux.mu.RLock()
	defer mux.mu.RUnlock()
	hs = mux.m[m.Command]
	hs = append(hs, mux.m[""]...)
	return hs
}

func (mux *Mux) Process(c *Client, m *Message) {
	hs := mux.Handler(m)
	if hs != nil {
		for _, h := range hs {
			go h.Process(c, m)
		}
	}
}

var DefaultMux = NewMux()

func Handle(command string, handler Handler) { DefaultMux.Handle(command, handler) }

func HandleFunc(command string, handler func(*Client, *Message)) {
	DefaultMux.HandleFunc(command, handler)
}

type Authenticator interface {
	Authenticate(c *Client)
}

type Muxer interface {
	Handler
	Handle(command string, handler Handler)
	HandleFunc(command string, handler func(*Client, *Message))
	Handler(m *Message) (hs []Handler)
}

type Client struct {
	Mux           Muxer
	TLSConfig     *tls.Config
	Authenticator Authenticator
	User          string
	Nick          string
	Name          string
	Password      string
	conn          net.Conn
	chErr         chan error
	chSend        chan string
	scanner       *bufio.Scanner
}

func (c *Client) Dial(network, addr string) error {
	conn, err := net.Dial(network, addr)
	if err != nil {
		return err
	}
	c.conn = conn
	return nil
}

func (c *Client) DialTLS(network, addr string) error {
	conn, err := tls.Dial(network, addr, c.TLSConfig)
	if err != nil {
		return err
	}
	c.conn = conn
	c.init()
	return nil
}

func (c *Client) init() {
	if c.Mux == nil {
		c.Mux = DefaultMux
	}
	c.chErr = make(chan error)
	c.chSend = make(chan string)
	c.scanner = bufio.NewScanner(c.conn)
	go c.writeLoop()
}

func (c *Client) Process() error {
	go c.readLoop()
	if c.Authenticator != nil {
		go c.Authenticator.Authenticate(c)
	} else {
		go c.Login()
	}
	return <-c.chErr
}

func (c *Client) Read() (*Message, error) {
	ok := c.scanner.Scan()
	if !ok {
		err := c.scanner.Err()
		if err == nil {
			return nil, io.EOF
		}
		return nil, err
	}
	return Parse(c.scanner.Text()), nil
}

func (c *Client) readLoop() {
	for {
		m, err := c.Read()
		if err != nil {
			c.chErr <- err
			return
		}
		log.Println("→", m.Raw)
		c.Mux.Process(c, m)
	}
}

func (c *Client) writeLoop() {
	for s := range c.chSend {
		log.Println("←", s) // TODO configurable logger
		_, err := io.WriteString(c.conn, s+"\n")
		if err != nil {
			c.chErr <- err
			return
		}
	}
}

func (c *Client) Login() {
	if len(c.Password) > 0 {
		c.Send(fmt.Sprintf("PASS %s", c.Password))
	}
	c.Send(fmt.Sprintf("USER %s 0 * :%s", c.User, c.Name))
	c.Send(fmt.Sprintf("NICK %s", c.Nick))
}

func (c *Client) Send(s string) {
	c.chSend <- s
}
