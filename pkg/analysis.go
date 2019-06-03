package stats

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
)

//GetStats generates cipher/protocol usage statistics using Wikipedia visitor data
func GetStats(forceDownload bool) (statistics TLSStatistics, e error) {
	force := forceDownload
	if force {
		if e = DownloadData(true); e == nil {
			renameCurrentStats()
			return analyseAndWriteToFile()
		}
		return
	}
	//check whether recent stats exists
	if _, err := os.Stat(jsonStatsOut); os.IsNotExist(err) {
		//no stats. download and compute
		e = DownloadData(false)
		return analyseAndWriteToFile()
	}
	//stats exist
	if data, e := ioutil.ReadFile(jsonStatsOut); e == nil {
		if e = json.Unmarshal(data, &statistics); e == nil {
			if statistics.GenerationDate.Before(time.Now().AddDate(0, -6, 0)) {
				//but it's stale
				//move the old stats
				renameCurrentStats()
				e = DownloadData(false)
				return analyseAndWriteToFile()
			}
		}
	}
	return
}

func analyseAndWriteToFile() (TLSStatistics, error) {
	stats, start, end := analyseStats(false)
	statistics := stats.toJSONStruct(start, end)
	data, err := json.MarshalIndent(statistics, "", " ")
	if err == nil {
		err = ioutil.WriteFile(jsonStatsOut, data, 0644)
	}
	return statistics, err
}

func renameCurrentStats() {
	if _, err := os.Stat(jsonStatsOut); !os.IsNotExist(err) {
		stats := TLSStatistics{}
		if data, err := ioutil.ReadFile(jsonStatsOut); err == nil && json.Unmarshal(data, &stats) == nil {
			jsonStatsOutBackup := path.Join(statsHome, fmt.Sprintf("tls-stats-%s.json", stats.GenerationDate.Format(dateFormat)))
			if err := os.Rename(jsonStatsOut, jsonStatsOutBackup); err != nil {
				log.Println(err.Error())
			}
		}
	}
}

//PrintStats prints cipher/protocol usage statistics using Wikipedia visitor data
func PrintStats(forceDownload bool) {
	DownloadData(forceDownload)
	stats, _, _ := analyseStats(false)
	fmt.Printf("Stats \n%s\n", stats)
	GetStats(false) //side effect, write JSON output

}

func analyseStats(forceDownload bool) (TLSStats, time.Time, time.Time) {

	browsers := loadBrowserOSStats(browserStatsData)
	devices := loadDeviceDetails(deviceCiphers)

	found := 0
	notfound := 0
	m := make(map[string]int)
	browserMap := make(map[string]int64)
	deviceKeys := make(map[string]bool)
	for _, d := range devices {
		deviceKeys[deviceKey(d)] = true
	}
	for _, b := range browsers {
		key := browserKey(b)
		if _, present := deviceKeys[key]; present {
			found++
			if count, present := browserMap[key]; present {
				browserMap[key] = count + b.Count
			} else {
				browserMap[key] = b.Count
			}
		} else {
			notfound++
			if count, ok := m[key]; ok {
				m[key] = count + 1
			} else {
				m[key] = 1
			}
		}

	}
	stats := getTLSStats(browserMap, devices)
	start, end := getDateRange(browsers)
	return stats, start, end
}

func getDateRange(browsers []Browser) (start, end time.Time) {
	if len(browsers) > 0 {
		start = browsers[0].Date
		end = browsers[0].Date
		for _, br := range browsers {
			date := br.Date
			if start.After(date) {
				start = date
			}
			if end.Before(date) {
				end = date
			}
		}
	}
	return
}

func getTLSStats(browsers map[string]int64, devices []Device) TLSStats {
	protocols := make(map[int]int64)
	ciphers := make(map[int]int64)
	curves := make(map[int]int64)

	deviceKeys := make(map[string]Device)
	for _, d := range devices {
		deviceKeys[deviceKey(d)] = d
	}

	total := int64(0)
	for b, c := range browsers {
		total += c
		if dev, found := deviceKeys[b]; found {
			//count protocol support
			lowestProtocol := 768 // limit protocols floor to SSL v3
			if dev.LowestProtocol > lowestProtocol {
				lowestProtocol = dev.LowestProtocol
			}
			for p := lowestProtocol; p <= dev.HighestProtocol; p++ {
				if count, present := protocols[p]; present {
					protocols[p] = count + c
				} else {
					protocols[p] = c
				}
			}

			//count cipher support
			for _, cid := range dev.SuiteIds {
				if count, present := ciphers[cid]; present {
					ciphers[cid] = count + c
				} else {
					ciphers[cid] = c
				}
			}

			//count elliptic curve support
			for _, cid := range dev.EllipticCurves {
				if count, present := curves[cid]; present {
					curves[cid] = count + c
				} else {
					curves[cid] = c
				}
			}

		} else {
			fmt.Printf("Could not find device with browser profile: %s\n", b)
		}
	}

	return TLSStats{
		Protocols: protocols,
		Ciphers:   ciphers,
		Curves:    curves,
		Total:     total,
		devices:   devices,
	}
}

func browserKey(browser Browser) string {
	return collapseVersion(fmt.Sprintf("%s:%s", dedupFamily(browser.BrowserFamily), browser.BrowserMajorVersion))
}

func dedupFamily(browser string) string {
	switch browser {
	case "Chrome Mobile":
		return "Chrome"
	case "Chrome Mobile WebView":
		return "Chrome"
	case "Chrome Mobile iOS":
		return "Chrome"
	case "Chromium":
		return "Chrome"
	case "Firefox Mobile":
		return "Firefox"
	case "Thunderbird":
		return "Firefox"
	case "Firefox iOS":
		return "Firefox"
	case "Opera Mini":
		return "Opera"
	case "Opera Mobile":
		return "Opera"
	case "Mobile Safari":
		return "Safari"
	case "Mobile Safari UIWebView":
		return "Safari"
	case "Mobile Safari UI/WKWebView":
		return "Safari"
	case "Samsung Internet":
		return "Android"
	case "IE Mobile":
		return "IE"
	case "Edge Mobile":
		return "Edge"
	default:
		return browser
	}
}

func collapseVersion(browser string) string {
	if fv := strings.Split(browser, ":"); len(fv) == 2 {
		fam := fv[0]
		ver := fv[1]
		switch fam {
		case "Chrome":
			if nv, present := chromeVers[ver]; present {
				return fmt.Sprintf("%s:%s", fam, nv)
			}
			return browser
		case "Firefox":
			if nv, present := firefoxVers[ver]; present {
				return fmt.Sprintf("%s:%s", fam, nv)
			}
			return browser
		case "Android":
			if nv, present := androidVers[ver]; present {
				return fmt.Sprintf("%s:%s", fam, nv)
			}
			return browser
		case "Safari":
			if nv, present := safariVers[ver]; present {
				return fmt.Sprintf("%s:%s", fam, nv)
			}
			return browser
		case "Opera":
			if nv, present := operaVers[ver]; present {
				return fmt.Sprintf("%s:%s", fam, nv)
			}
			return browser
		case "Edge":
			if nv, present := edgeVers[ver]; present {
				return fmt.Sprintf("%s:%s", fam, nv)
			}
			return browser
		case "IE":
			if nv, present := ieVers[ver]; present {
				return fmt.Sprintf("%s:%s", fam, nv)
			}
			return browser
		default:
			return browser

		}
	}

	return browser

}

func deviceKey(device Device) string {
	return fmt.Sprintf("%s:%s", device.Name, device.Version)
}

//load about 1 year's worth of data.
func loadBrowserOSStats(file string) (browsers []Browser) {
	year, _, _ := time.Now().Date()
	yearAgo := time.Date(year-1, 0, 0, 0, 0, 0, 0, time.UTC) // a year ago and a bit
	if f, err := os.Open(file); err == nil {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			data := strings.Split(line, "\t")
			if len(data) > 4 {
				if percent, err := strconv.ParseInt(data[5], 10, 64); err == nil {
					if date, err := time.Parse(dateFormat, data[0]); err == nil && date.After(yearAgo) {
						browser := Browser{
							Date:                date,
							BrowserFamily:       data[3],
							BrowserMajorVersion: data[4],
							OSFamily:            data[1],
							OSMajorVersion:      data[2],
							Count:               percent,
						}
						browsers = append(browsers, browser)
					}
				}
			}
		}
	}

	//limit to about one year's worth of data
	if length := len(browsers) - 1; length > 0 {
		lastDate := browsers[length].Date
		yearAgo = lastDate.AddDate(-1, 0, 0)
		records := []Browser{}
		for _, b := range browsers {
			if b.Date.After(yearAgo) {
				records = append(records, b)
			}
		}
		browsers = records
	}

	return
}

func loadDeviceDetails(file string) (devices []Device) {
	if f, err := os.Open(file); err == nil {
		defer f.Close()
		if bytes, err := ioutil.ReadAll(f); err == nil {
			json.Unmarshal(bytes, &devices)
		}
	}
	return
}
