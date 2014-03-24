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
	"time"
	"unicode"
	"unicode/utf8"
)

type Mask struct {
	Nick string
	User string
	Host string
}

type Message struct {
	// The raw IRC message
	Raw     string
	Prefix  Mask
	Command string
	Params  []string
	// The signal/command name to use for routing. In most cases, this
	// will equal the command. In some cases, such as CTCP messages,
	// it will be different.
	Signal string
}

// Copy performs a deep copy of a message. This is useful when passing
// messages to functions that should have ownership over the message,
// including the slice of parameters. Usually this will be used when
// implementing muxers.
func (m *Message) Copy() *Message {
	m2 := *m
	m2.Params = make([]string, len(m.Params))
	copy(m2.Params, m.Params)
	return &m2
}

func pad(in []string, n int) []string {
	if len(in) == n {
		return in
	}
	out := make([]string, n)
	copy(out, in)
	return out
}

// Parse parses an IRC message as it may be sent or received.
func Parse(s string) *Message {
	m := &Message{Raw: s}

	if s[0] == ':' {
		parts := pad(strings.SplitN(s, " ", 3), 3)
		prefix := parts[0][1:]
		if strings.Index(prefix, "!") == -1 {
			m.Prefix.Host = prefix
		} else {
			parts := strings.FieldsFunc(prefix, func(r rune) bool { return r == '!' || r == '@' })
			parts = pad(parts, 3)
			m.Prefix.Nick = parts[0]
			m.Prefix.User = parts[1]
			m.Prefix.Host = parts[2]
		}
		m.Command = parts[1]
		m.Signal = m.Command
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

// IsNumeric reports whether the message's command is numeric (e.g.
// 001) as opposed to a string (e.g. "JOIN".)
func (m *Message) IsNumeric() bool {
	if len(m.Command) != 3 {
		return false
	}
	s := m.Command
	return s[0] >= '0' && s[0] <= '9' &&
		s[1] >= '0' && s[1] <= '9' &&
		s[2] >= '0' && s[2] <= '9'
}

// IsError reports whether the message's command denotes an error,
// i.e. whether it is numeric and the number code starts with either a
// 4 or a 5.
func (m *Message) IsError() bool {
	return m.IsNumeric() && (m.Command[0] == '4' || m.Command[0] == '5')
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
	return mux
}

func (mux *Mux) Handle(signal string, handler Handler) {
	mux.mu.Lock()
	defer mux.mu.Unlock()
	mux.m[signal] = append(mux.m[signal], handler)
}

func (mux *Mux) HandleFunc(signal string, handler func(*Client, *Message)) {
	mux.Handle(signal, HandlerFunc(handler))
}

func (mux *Mux) Handlers(m *Message) (hs []Handler) {
	mux.mu.RLock()
	defer mux.mu.RUnlock()
	hs = mux.m[m.Signal]
	hs = append(hs, mux.m[""]...)
	return hs
}

func (mux *Mux) Process(c *Client, m *Message) {
	hs := mux.Handlers(m)
	if hs != nil {
		for _, h := range hs {
			m := m.Copy()
			go h.Process(c, m.Copy())
		}
	}
}

var DefaultMux = NewMux()

func Handle(signal string, handler Handler) { DefaultMux.Handle(signal, handler) }

func HandleFunc(signal string, handler func(*Client, *Message)) {
	DefaultMux.HandleFunc(signal, handler)
}

type Authenticator interface {
	Authenticate(c *Client)
}

type Muxer interface {
	Handler
	Handle(command string, handler Handler)
	HandleFunc(command string, handler func(*Client, *Message))
	Handlers(m *Message) (hs []Handler)
}

type Client struct {
	mu            sync.RWMutex
	Mux           Muxer
	TLSConfig     *tls.Config
	Authenticator Authenticator
	User          string
	Nick          string
	Name          string
	Password      string
	// TODO proper documentation. The ISupport field will be
	// automatically set to a default value during dialing and will
	// then be populated by the IRC server.
	ISupport    *ISupport
	currentNick string
	connected   []string
	conn        net.Conn
	chErr       chan error
	chSend      chan string
	scanner     *bufio.Scanner
}

func inStrings(in []string, s string) bool {
	for _, e := range in {
		if e == s {
			return true
		}
	}
	return false
}

func (c *Client) Connected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return inStrings(c.connected, "422") ||
		(inStrings(c.connected, "001") &&
			inStrings(c.connected, "002") &&
			inStrings(c.connected, "003") &&
			inStrings(c.connected, "004"))
}

func (c *Client) Dial(network, addr string) error {
	conn, err := net.Dial(network, addr)
	if err != nil {
		return err
	}
	c.conn = conn
	c.init()
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
	c.ISupport = NewISupport()
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
	c.conn.SetReadDeadline(time.Now().Add(240 * time.Second))
	m := Parse(c.scanner.Text())
	switch m.Command {
	case "PING":
		c.Sendf("PONG %s", m.Params[0])
	case RPL_ISUPPORT:
		c.ISupport.Parse(m)
	case "001", "002", "003", "004", "422":
		c.mu.Lock()
		c.connected = append(c.connected, m.Command)
		c.currentNick = m.Params[0]
		c.mu.Unlock()

		if c.Connected() {
			c.Mux.Process(c, &Message{Signal: "irc:connected"})
		}
	case "NICK":
		// We don't need to lock for reading here, there is no
		// concurrent writer to c.currentNick
		if m.Prefix.Nick != c.currentNick {
			break
		}
		c.mu.Lock()
		c.currentNick = m.Params[0]
		c.mu.Unlock()
	}

	return m, nil
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
		c.conn.SetWriteDeadline(time.Now().Add(240 * time.Second))
		_, err := io.WriteString(c.conn, s+"\n")
		if err != nil {
			c.chErr <- err
			return
		}
	}
}

func (c *Client) Login() {
	if len(c.Password) > 0 {
		c.Sendf("PASS %s", c.Password)
	}
	c.Sendf("USER %s 0 * :%s", c.User, c.Name)
	c.Sendf("NICK %s", c.Nick)
}

func (c *Client) Send(s string) {
	c.chSend <- s
}

func (c *Client) Sendf(format string, args ...interface{}) {
	c.Send(fmt.Sprintf(format, args...))
}

// Privmsg sends a PRIVMSG message to target.
func (c *Client) Privmsg(target, message string) {
	c.Sendf("PRIVMSG %s :%s", target, message)
}

// PrivmsgSplit sends a PRIVMSG message to target and splits it into
// chunks of n. See SplitMessage for more information on how said
// splitting is done.
func (c *Client) PrivmsgSplit(target, message string, n int) {
	s := fmt.Sprintf("PRIVMSG %s :%s", target, message)
	for _, msg := range SplitMessage(s, n) {
		c.Send(msg)
	}
}

// Notice sends a NOTICE message to target.
func (c *Client) Notice(target, message string) {
	c.Sendf("NOTICE %s :%s", target, message)
}

// NoticeSplit sends a NOTICE message to target and splits it into
// chunks of n. See SplitMessage for more information on how said
// splitting is done.
func (c *Client) NoticeSplit(target, message string, n int) {
	s := fmt.Sprintf("NOTICE %s :%s", target, message)
	for _, msg := range SplitMessage(s, n) {
		c.Send(msg)
	}
}

func (c *Client) Reply(m *Message, response string) {
	if m.Command != "PRIVMSG" && m.Command != "NOTICE" {
		panic("cannot reply to " + m.Command)
	}
	target, ok := c.ChannelForMsg(m)
	if !ok {
		// TODO message was sent to us directly, not a channel
		target = m.Prefix.Nick
	}
	c.Privmsg(target, response)
}

func (c *Client) ReplySplit(m *Message, response string, n int) {
	if m.Command != "PRIVMSG" && m.Command != "NOTICE" {
		panic("cannot reply to " + m.Command)
	}
	target, ok := c.ChannelForMsg(m)
	if !ok {
		// message was sent to us directly, not a channel
		target = m.Prefix.Nick
	}
	c.PrivmsgSplit(target, response, n)
}

func inRunes(runes []rune, search rune) bool {
	for _, rune := range runes {
		if rune == search {
			return true
		}
	}
	return false
}

func (c *Client) ChannelForMsg(m *Message) (string, bool) {
	if len(m.Params) == 0 {
		return "", false
	}
	switch m.Command {
	case "INVITE", RPL_CHANNELMODEIS, RPL_BANLIST:
		return m.Params[1], true
	case RPL_NAMEREPLY:
		return m.Params[2], true
	default:
		if inRunes(c.ISupport.ChanTypes, []rune(m.Params[0])[0]) {
			return m.Params[0], true
		}
		if m.IsNumeric() && len(m.Params) > 1 && inRunes(c.ISupport.ChanTypes, []rune(m.Params[1])[0]) {
			return m.Params[1], true
		}
	}
	return "", false
}

// SplitMessage splits a PRIVMSG or NOTICE into many messages, each at
// most n bytes long and repeating the command and target list. Split
// assumes UTF-8 encoding but does not support combining characters.
// It does not split in the middle of words.
//
// IRC messages can be at most 512 bytes long. This includes the
// terminating \r\n as well as the message prefix that the server
// prepends, consisting of a : sign and a hostmask. For optimal
// results, n should be calculated accordingly, but a safe value that
// doesn't require calculations would be around 350.
//
// The result is undefined if n is smaller than the command and target
// portions or if the list of targets is missing. If a single word is
// longer than n bytes, it will be split.
func SplitMessage(s string, n int) []string {
	if len(s) < n || !utf8.ValidString(s) {
		return []string{s}
	}
	pl := strings.Index(s, " :") + 2
	repeat := s[:pl]
	s = s[pl:]

	n -= pl
	if n <= 0 {
		n = 1
	}

	var parts []string
	for len(s) > n {
		pos := strings.LastIndex(s[:n], " ")
		if pos == -1 {
			pos = n
		}
		dir := -1
		for {
			if r, size := utf8.DecodeLastRuneInString(s[:pos]); r != utf8.RuneError || size != 1 {
				break
			}
			pos += dir
			if pos == 0 {
				pos = 1
				dir = 1
			}
		}
		parts = append(parts, s[:pos])
		s = strings.TrimLeftFunc(s[pos:], unicode.IsSpace)
	}
	if len(s) > 0 {
		parts = append(parts, s)
	}
	for i := range parts {
		parts[i] = repeat + parts[i]
	}
	return parts
}

func (c *Client) Join(channel, password string) {
	// FIXME do not return until we actually joined the channel. or
	// maybe put that in the framework?
	if password == "" {
		c.Sendf("JOIN %s", channel)
	} else {
		c.Sendf("JOIN %s %s", channel, password)
	}
}

func (c *Client) SetNick(nick string) {
	c.Sendf("NICK %s", nick)
}

func (c *Client) CurrentNick() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.currentNick
}
