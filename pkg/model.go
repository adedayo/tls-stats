package stats

import (
	"crypto/tls"
	"fmt"
	"sort"
	"time"
)

//TLSStatistics for JSON output
type TLSStatistics struct {
	GenerationDate time.Time //date this stats was generated
	StartDate      time.Time //the date of first entry used to calculate the stats
	EndDate        time.Time //the date of last entry used to calculate the stats
	Protocols      []Entry
	Ciphers        []Entry
	Curves         []Entry
}

//ToMapped generates a version of TLSStatistics with easy 'lookup'
func (t TLSStatistics) ToMapped() (m MappedTLSStatistics) {
	data := make(map[int]Entry)
	for _, x := range t.Protocols {
		data[x.ID] = x
	}
	m.Protocols = data
	data = make(map[int]Entry)
	for _, x := range t.Ciphers {
		data[x.ID] = x
	}
	m.Ciphers = data
	data = make(map[int]Entry)
	for _, x := range t.Curves {
		data[x.ID] = x
	}
	m.Curves = data
	return
}

//MappedTLSStatistics is a version of TLSStatistics in 'Map' form
type MappedTLSStatistics struct {
	Protocols map[int]Entry
	Ciphers   map[int]Entry
	Curves    map[int]Entry
}

//Entry TLS statistic entry
type Entry struct {
	ID      int
	Percent float64
	Name    string
}

type intByInt64 struct {
	k int
	v int64
}
type kv []intByInt64

func (s kv) Len() int {
	return len(s)
}
func (s kv) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}
func (s kv) Less(i, j int) bool {
	return s[i].v > s[j].v
}

//TLSStats contains statistics about TLS usage in the last year or so
type TLSStats struct {
	Protocols map[int]int64
	Ciphers   map[int]int64
	Curves    map[int]int64
	Total     int64 //Total number of browsers/devices used in these stats

	//internal data
	devices   []Device
	protocols kv
	ciphers   kv
	curves    kv
}

func (stats TLSStats) toJSONStruct(start, end time.Time) TLSStatistics {
	stats.sort()
	protocols := []Entry{}
	for _, pp := range stats.protocols {
		p := pp.k
		v := pp.v
		name := getProtocolName(p)
		percent := float64(v) / float64(stats.Total)
		protocols = append(protocols, Entry{
			ID:      p,
			Percent: percent,
			Name:    name,
		})
	}

	ciphersWithNonStandardNames := cipherMaps(stats.devices)
	ciphers := []Entry{}
	for _, cc := range stats.ciphers {
		c := cc.k
		v := cc.v
		percent := float64(v) / float64(stats.Total)
		name := getCipherName(c, ciphersWithNonStandardNames)
		ciphers = append(ciphers, Entry{
			ID:      c,
			Percent: percent,
			Name:    name,
		})

	}
	curves := []Entry{}

	for _, cc := range stats.curves {
		c := cc.k
		v := cc.v
		percent := float64(v) / float64(stats.Total)
		name := getCurveName(c)
		curves = append(curves, Entry{
			ID:      c,
			Percent: percent,
			Name:    name,
		})
	}
	year, month, day := time.Now().Date()
	return TLSStatistics{
		GenerationDate: time.Date(year, month, day, 0, 0, 0, 0, time.UTC),
		StartDate:      start,
		EndDate:        end,
		Protocols:      protocols,
		Ciphers:        ciphers,
		Curves:         curves,
	}
}
func (stats TLSStats) String() (out string) {
	now := time.Now()
	st := stats.toJSONStruct(now, now)
	out += fmt.Sprintf("Protocols\n=============\n")

	for _, e := range st.Protocols {
		out += fmt.Sprintf("\t%d\t%f\t%s\n", e.ID, e.Percent, e.Name)
	}

	out += fmt.Sprintf("Ciphers\n=============\n")
	for _, e := range st.Ciphers {
		out += fmt.Sprintf("\t%d\t%f\t%s\n", e.ID, e.Percent, e.Name)
	}

	out += fmt.Sprintf("Curves\n=============\n")
	for _, e := range st.Curves {
		out += fmt.Sprintf("\t%d\t%f\t%s\n", e.ID, e.Percent, e.Name)
	}

	return
}

func (stats *TLSStats) sort() {
	data := kv{}
	for k, v := range stats.Protocols {
		data = append(data, intByInt64{k, v})
	}
	sort.Sort(data)
	stats.protocols = data

	data = kv{}
	for k, v := range stats.Ciphers {
		data = append(data, intByInt64{k, v})
	}
	sort.Sort(data)
	stats.ciphers = data

	data = kv{}
	for k, v := range stats.Ciphers {
		data = append(data, intByInt64{k, v})
	}
	sort.Sort(data)
	stats.ciphers = data

	data = kv{}
	for k, v := range stats.Curves {
		data = append(data, intByInt64{k, v})
	}
	sort.Sort(data)
	stats.curves = data

}

func cipherMaps(devices []Device) map[int]string {
	out := make(map[int]string)
	for _, dev := range devices {
		for ind, id := range dev.SuiteIds {
			if _, present := out[id]; !present {
				out[id] = dev.SuiteNames[ind]
			}
		}
	}
	return out
}

func getProtocolName(p int) string {
	switch p {
	case tls.VersionSSL30:
		return "SSL v3.0"
	case tls.VersionTLS10:
		return "TLS v1.0"
	case tls.VersionTLS11:
		return "TLS v1.1"
	case tls.VersionTLS12:
		return "TLS v1.2"
	case tls.VersionTLS13:
		return "TLS v1.3"
	default:
		return "Unknown Protocol"
	}
}

func getCipherName(c int, nonStandard map[int]string) string {
	if cipher, present := CipherSuiteMap[uint16(c)]; present {
		return cipher
	} else if cipher, present := nonStandard[c]; present {
		return cipher
	}
	return "Nonstandard Cipher"
}

func getCurveName(c int) string {
	if curve, present := NamedCurves[uint16(c)]; present {
		return curve
	}
	return "Nonstandard Curve"
}

//Device models a device and its supported ciphers and protocols
type Device struct {
	Name            string
	Platform        string
	Version         string
	LowestProtocol  int
	HighestProtocol int
	SuiteIds        []int
	SuiteNames      []string
	EllipticCurves  []int
}

//Browser models a Browser and OS along with the count of how many times it shows up
type Browser struct {
	Date                time.Time
	BrowserFamily       string
	BrowserMajorVersion string
	OSFamily            string
	OSMajorVersion      string
	Count               int64
}

func (b Browser) String() string {
	return fmt.Sprintf("stats.Browser{Date: %s, Browser: %s, MajorVersion: %s, OS: %s, OSVersion: %s, Count: %d}", b.Date.Format(dateFormat), b.BrowserFamily, b.BrowserMajorVersion,
		b.OSFamily, b.OSMajorVersion, b.Count)
}
