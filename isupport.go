package irc

import (
	"strconv"
	"strings"
)

type ChanModes struct {
	A []rune
	B []rune
	C []rune
	D []rune
}

type ISupport struct {
	AwayLen     int
	CNOTICE     bool
	CPRIVMSG    bool
	CaseMapping string
	ChanLimit   map[rune]int
	ChanModes   ChanModes
	ChanTypes   []rune
	ChannelLen  int
	ChidLen     int
	ETRACE      bool
	ELIST       []rune
	Excepts     bool
	FNC         bool
	Invex       bool
	KickLen     int
	Knock       bool
	MaxBans     int
	MaxChannels int
	MaxList     map[rune]int
	MaxTargets  int
	Modes       int
	Monitor     int
	Network     string
	NickLen     int
	Prefix      map[rune]rune
	Silence     int
	StatusMsg   []rune
	TargMax     map[string]int
	TopicLen    int
	Watch       int
	// TODO IDCHAN pfx:num[,pfx:num,...]
	// TODO CALLERID (with and without argument)
	// TODO DEAF
	// TODO EXTBAN=$,arxz
	// TODO WHOX
	// TODO CLIENTVER=3.0
	// TODO SAFELIST
}

func NewISupport() *ISupport {
	return &ISupport{
		Modes:       3,
		NickLen:     9,
		ChanLimit:   map[rune]int{},
		Prefix:      map[rune]rune{'o': '@', 'v': '+'},
		MaxList:     map[rune]int{},
		TargMax:     map[string]int{},
		CaseMapping: "rfc1459",
	}
}

func (is *ISupport) setBool(name string, value bool) {
	switch name {
	case "EXCEPTS":
		is.Excepts = value
	case "INVEX":
		is.Invex = value
	case "KNOCK":
		is.Knock = value
	case "ETRACE":
		is.ETRACE = value
	case "CPRIVMSG":
		is.CPRIVMSG = value
	case "CNOTICE":
		is.CNOTICE = value
	case "FNC":
		is.FNC = value
	}
}

func (is *ISupport) setInt(name string, value int) {
	switch name {
	case "MODES":
		is.Modes = value
	case "NICKLEN":
		is.NickLen = value
	case "CHANNELLEN":
		is.ChannelLen = value
	case "TOPICLEN":
		is.TopicLen = value
	case "MONITOR":
		is.Monitor = value
	case "MAXCHANNELS":
		is.MaxChannels = value
	case "MAXBANS":
		is.MaxBans = value
	case "KICKLEN":
		is.KickLen = value
	case "CHIDLEN":
		is.ChidLen = value
	case "SILENCE":
		is.Silence = value
	case "AWAYLEN":
		is.AwayLen = value
	case "WATCH":
		is.Watch = value
	case "MAXTARGETS":
		is.MaxTargets = value
	}
}

// Parse parses a RPL_ISUPPORT message and sets the contained options.
// Parse can be called multiple times to build a full ISUPPORT
// representation from multiple messages.
func (is *ISupport) Parse(m *Message) {
	if m.Command != RPL_ISUPPORT {
		return
	}

	for _, option := range m.Params[1:] {
		parts := strings.Split(option, "=")
		parts = pad(parts, 2)
		switch parts[0] {
		case "EXCEPTS", "INVEX", "KNOCK", "ETRACE", "CPRIVMSG", "CNOTICE", "FNC":
			is.setBool(parts[0], true)
		case "MODES", "NICKLEN", "CHANNELLEN", "TOPICLEN", "MONITOR", "MAXCHANNELS",
			"MAXBANS", "KICKLEN", "CHIDLEN", "SILENCE", "AWAYLEN", "WATCH", "MAXTARGETS":
			i, err := strconv.Atoi(parts[1])
			if err != nil {
				continue
			}
			is.setInt(parts[0], i)
		case "NETWORK":
			is.Network = parts[1]
		case "CASEMAPPING":
			is.CaseMapping = parts[1]
		case "CHANMODES":
			modes := strings.Split(parts[1], ",")
			modes = pad(modes, 4)
			is.ChanModes.A = []rune(modes[0])
			is.ChanModes.B = []rune(modes[1])
			is.ChanModes.C = []rune(modes[2])
			is.ChanModes.D = []rune(modes[3])
		case "CHANTYPES":
			is.ChanTypes = []rune(parts[1])
		case "CHANLIMIT":
			if is.ChanLimit == nil {
				is.ChanLimit = make(map[rune]int)
			}
			m := splitPrefixNum(parts[1])
			for key, value := range m {
				for _, r := range key {
					is.ChanLimit[r] = value
				}
			}
		case "ELIST":
			is.ELIST = []rune(parts[1])
		case "PREFIX":
			if is.Prefix == nil {
				is.Prefix = make(map[rune]rune)
			}
			if len(parts[1]) < 4 {
				continue
			}
			idx := strings.Index(parts[1], ")")
			if idx == -1 || idx == len(parts[1])-1 {
				continue
			}
			letters, sigils := []rune(parts[1][1:idx]), []rune(parts[1][idx+1:])
			if len(letters) != len(sigils) {
				continue
			}
			for i, l := range letters {
				is.Prefix[l] = sigils[i]
			}
		case "TARGMAX":
			is.TargMax = splitPrefixNum(parts[1])
		case "MAXLIST":
			if is.MaxList == nil {
				is.MaxList = make(map[rune]int)
			}
			m := splitPrefixNum(parts[1])
			for modes, n := range m {
				for _, mode := range modes {
					is.MaxList[mode] = n
				}
			}
		case "STATUSMSG":
			is.StatusMsg = []rune(parts[1])
		}
	}
}

func splitPrefixNum(pairs string) map[string]int {
	m := make(map[string]int)
	for _, pair := range strings.Split(pairs, ",") {
		parts := strings.Split(pair, ":")
		name := parts[0]
		num := -1
		if len(parts[1]) > 0 {
			num, _ = strconv.Atoi(parts[1])
		}
		m[name] = num
	}
	return m
}
