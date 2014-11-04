package irc

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

const CTCPDelim = "\001"

type Logger interface {
	Incoming(*Message)
	Outgoing(*Message)
	Info(...interface{})
	Debug(...interface{})
	Panic(interface{})
}

// RawLogger only logs incoming and outgoing messages in their raw
// form. To differentiate incoming from outgoing messages, it prefixes
// incoming messages with -> and outgoing messages with <-, in
// addition to a timestamp.
type RawLogger struct {
	mu sync.Mutex
	W  io.Writer
}

func (l *RawLogger) Incoming(m *Message) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.W, "%s -> %s\n", time.Now().Format(time.RFC3339), m.Raw)
}

func (l *RawLogger) Outgoing(m *Message) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.W, "%s <- %s\n", time.Now().Format(time.RFC3339), m.Raw)
}

func (l *RawLogger) Info(...interface{})  {}
func (l *RawLogger) Debug(...interface{}) {}
func (l *RawLogger) Panic(interface{})    {}

// FormattedLogger is a generic logger that supports all types of log
// messages and prefixes them with tags as well as timestamps.
//
// Example output:
// 2009-11-10T23:00:00Z [INC  ] Incoming message
// 2009-11-10T23:00:01Z [OUT  ] Outgoing message
// 2009-11-10T23:00:02Z [INFO ] Info message
// 2009-11-10T23:00:03Z [DEBUG] Debug messages
// 2009-11-10T23:00:04Z [PANIC] Panic message
// 2009-11-10T23:00:04Z [PANIC] Stacktrace line 1
// ...
type FormattedLogger struct {
	mu sync.Mutex
	W  io.Writer
}

func (l *FormattedLogger) Incoming(m *Message) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.W, "%s [INC  ] %s\n", time.Now().Format(time.RFC3339), m.Raw)
}

func (l *FormattedLogger) Outgoing(m *Message) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.W, "%s [OUT  ] %s\n", time.Now().Format(time.RFC3339), m.Raw)
}

func (l *FormattedLogger) Info(args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.W, "%s [INFO ] ", time.Now().Format(time.RFC3339))
	fmt.Fprintln(l.W, args...)
}

func (l *FormattedLogger) Debug(args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.W, "%s [DEBUG] ", time.Now().Format(time.RFC3339))
	fmt.Fprintln(l.W, args...)
}

func (l *FormattedLogger) Panic(arg interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.W, "%s [PANIC] ", time.Now().Format(time.RFC3339))
	fmt.Fprintln(l.W, arg)
	buf := make([]byte, 64<<10)
	n := runtime.Stack(buf, false)
	s := string(buf[:n])
	lines := strings.Split(s, "\n")
	for _, line := range lines {
		fmt.Fprintf(l.W, "%s [PANIC] %s\n", time.Now().Format(time.RFC3339), line)
	}
}

// MultiLogger allows using multiple log targets at once. All log
// messages get sent to all loggers.
type MultiLogger struct {
	Loggers []Logger
}

func (l *MultiLogger) Incoming(m *Message) {
	for _, ll := range l.Loggers {
		ll.Incoming(m)
	}
}

func (l *MultiLogger) Outgoing(m *Message) {
	for _, ll := range l.Loggers {
		ll.Outgoing(m)
	}
}

func (l *MultiLogger) Info(args ...interface{}) {
	for _, ll := range l.Loggers {
		ll.Info(args...)
	}
}

func (l *MultiLogger) Debug(args ...interface{}) {
	for _, ll := range l.Loggers {
		ll.Debug(args...)
	}
}

func (l *MultiLogger) Panic(arg interface{}) {
	for _, ll := range l.Loggers {
		ll.Panic(arg)
	}
}

type nullLogger struct{}

func (nullLogger) Incoming(*Message)    {}
func (nullLogger) Outgoing(*Message)    {}
func (nullLogger) Info(...interface{})  {}
func (nullLogger) Debug(...interface{}) {}
func (nullLogger) Panic(interface{})    {}

var _ Logger = (*RawLogger)(nil)
var _ Logger = (*FormattedLogger)(nil)
var _ Logger = (*MultiLogger)(nil)
var _ Logger = (*nullLogger)(nil)

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
	m.Signal = m.Command
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
	Raw     string
	Command string
	Params  []string
}

func ParseCTCP(s string) (*CTCPMessage, error) {
	if len(s) < 2 {
		return nil, errors.New("not a CTCP message")
	}
	s = s[1 : len(s)-1]
	m := &CTCPMessage{Raw: s}
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
	Authenticator Authenticator
	Err           error
	// TODO proper documentation. The ISupport field will be
	// automatically set to a default value during dialing and will
	// then be populated by the IRC server.
	ISupport    *ISupport
	Logger      Logger
	Mux         Muxer
	Name        string
	Nick        string
	Password    string
	TLSConfig   *tls.Config
	User        string
	mu          sync.RWMutex
	currentNick string
	connected   []string
	conn        net.Conn
	chSend      chan string
	chQuit      chan struct{}
	scanner     *bufio.Scanner
	dead        bool
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
	return inStrings(c.connected, ERR_NOMOTD) ||
		(inStrings(c.connected, RPL_WELCOME) &&
			inStrings(c.connected, RPL_YOURHOST) &&
			inStrings(c.connected, RPL_CREATED) &&
			inStrings(c.connected, RPL_MYINFO))
}

var ErrDeadClient = errors.New("dead client")

func (c *Client) Dial(network, addr string) error {
	c.mu.Lock()
	if c.dead {
		return ErrDeadClient
	}
	c.mu.Unlock()

	conn, err := net.Dial(network, addr)
	if err != nil {
		return err
	}
	c.conn = conn
	c.init()
	return nil
}

func (c *Client) DialTLS(network, addr string) error {
	c.mu.Lock()
	if c.dead {
		return ErrDeadClient
	}
	c.mu.Unlock()

	conn, err := tls.Dial(network, addr, c.TLSConfig)
	if err != nil {
		return err
	}
	c.conn = conn
	c.init()
	return nil
}

func (c *Client) init() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Mux == nil {
		c.Mux = DefaultMux
	}
	if c.Logger == nil {
		c.Logger = nullLogger{}
	}
	c.ISupport = NewISupport()
	c.chSend = make(chan string)
	c.chQuit = make(chan struct{})
	c.scanner = bufio.NewScanner(c.conn)
	c.connected = nil
	c.currentNick = ""
	go c.writeLoop()
}

func (c *Client) error(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Err != nil {
		return
	}
	c.Err = err
	c.dead = true
	c.conn.Close()
	close(c.chQuit)
}

func (c *Client) Process() error {
	go c.pingLoop()
	if c.Authenticator != nil {
		go c.Authenticator.Authenticate(c)
	} else {
		go c.Login()
	}
	return c.readLoop()
}

type readReply struct {
	msg *Message
	err error
}

func (c *Client) read(ch chan readReply) {
	ok := c.scanner.Scan()
	if !ok {
		err := c.scanner.Err()
		if err == nil {
			err = io.EOF
		}
		c.error(err)
		return
	}
	c.conn.SetReadDeadline(time.Now().Add(240 * time.Second))
	m := Parse(c.scanner.Text())
	ch <- readReply{m, nil}
}

func (c *Client) Read() (*Message, error) {
	select {
	case <-c.chQuit:
		return nil, c.Err
	default:
	}

	ch := make(chan readReply, 1)
	go c.read(ch)
	select {
	case reply := <-ch:
		m := reply.msg
		c.Logger.Incoming(m)
		switch m.Command {
		case "PING":
			c.Sendf("PONG %s", reply.msg.Params[0])
		case RPL_ISUPPORT:
			c.ISupport.Parse(m)
		case RPL_WELCOME, RPL_YOURHOST, RPL_CREATED, RPL_MYINFO, ERR_NOMOTD:
			c.mu.Lock()
			c.connected = append(c.connected, m.Command)
			c.currentNick = m.Params[0]
			c.mu.Unlock()
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
		return reply.msg, reply.err
	case <-c.chQuit:
		return nil, c.Err
	}
}

func (c *Client) pingLoop() {
	ticker := time.NewTicker(120 * time.Second)
	for {
		select {
		case <-ticker.C:
			c.Send("PING :0")
		case <-c.chQuit:
			return
		}
	}
}

func (c *Client) readLoop() error {
	for {
		m, err := c.Read()
		if err != nil {
			return err
		}

		switch m.Command {
		case RPL_WELCOME, RPL_YOURHOST, RPL_CREATED, RPL_MYINFO, ERR_NOMOTD:
			if c.Connected() {
				c.Mux.Process(c, &Message{Signal: "irc:connected"})
			}
		case "PRIVMSG", "NOTICE":
			if ctcp, err := m.CTCP(); err == nil {
				m := m.Copy()
				m.Signal = "ctcp:" + ctcp.Command
				c.Mux.Process(c, m)
			}
		}

		c.Mux.Process(c, m)
	}
}

func (c *Client) writeLoop() {
	for {
		select {
		case s := <-c.chSend:
			c.Logger.Outgoing(Parse(s))
			c.conn.SetWriteDeadline(time.Now().Add(240 * time.Second))
			_, err := io.WriteString(c.conn, s+"\r\n")
			if err != nil {
				c.error(err)
			}
		case <-c.chQuit:
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
	select {
	case c.chSend <- s:
	case <-c.chQuit:
	}
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

func (c *Client) ReplyCTCP(m *Message, response string) {
	if !m.IsCTCP() {
		panic("message is not a CTCP")
	}
	ctcp, _ := m.CTCP()
	c.Notice(m.Prefix.Nick, fmt.Sprintf("%s%s %s%s", CTCPDelim, ctcp.Command, response, CTCPDelim))
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
