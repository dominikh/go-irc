package irc

import (
	"reflect"
	"testing"
)

func TestISupport(t *testing.T) {
	const completeAndUnknown = ":prefix 005 recipient AWAYLEN=1 CNOTICE CPRIVMSG CASEMAPPING=ascii CHANLIMIT=#&:2,!:3 CHANMODES=beI,k,l,imnpstaqr CHANTYPES=#& CHANNELLEN=4 CHIDLEN=5 ETRACE ELIST=MNUCT EXCEPTS FNC INVEX KICKLEN=6 KNOCK MAXBANS=7 MAXCHANNELS=8 MAXLIST=be:9,I:8 MAXTARGETS=7 MODES=6 MONITOR=7 NETWORK=some_network NICKLEN=13 PREFIX=(ohv)@%+ SILENCE=42 STATUSMSG=+@ TARGMAX=PRIVMSG:55,NOTICE: TOPICLEN=66 WATCH=32 UNKNOWN=foobar"

	is := NewISupport()
	is.Parse(Parse(completeAndUnknown))

	expected := &ISupport{
		AwayLen:     1,
		CNOTICE:     true,
		CPRIVMSG:    true,
		CaseMapping: "ascii",
		ChanLimit:   map[rune]int{'#': 2, '&': 2, '!': 3},
		ChanModes: ChanModes{
			A: []rune("beI"),
			B: []rune("k"),
			C: []rune("l"),
			D: []rune("imnpstaqr"),
		},
		ChanTypes:   []rune("#&"),
		ChannelLen:  4,
		ChidLen:     5,
		ETRACE:      true,
		ELIST:       []rune("MNUCT"),
		Excepts:     true,
		FNC:         true,
		Invex:       true,
		KickLen:     6,
		Knock:       true,
		MaxBans:     7,
		MaxChannels: 8,
		MaxList:     map[rune]int{'b': 9, 'e': 9, 'I': 8},
		MaxTargets:  7,
		Modes:       6,
		Monitor:     7,
		Network:     "some_network",
		NickLen:     13,
		Prefix:      map[rune]rune{'o': '@', 'h': '%', 'v': '+'},
		Silence:     42,
		StatusMsg:   []rune("+@"),
		TargMax:     map[string]int{"PRIVMSG": 55, "NOTICE": -1},
		TopicLen:    66,
		Watch:       32,
	}

	if !reflect.DeepEqual(expected, is) {
		t.Errorf("parsing isupport: expected %#v, got %#v", expected, is)
	}
}
