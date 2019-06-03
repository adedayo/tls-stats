package stats

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"time"

	homedir "github.com/mitchellh/go-homedir"
)

//BrowserStats Wikipedia OS and Browser counts
var BrowserStats = "https://analytics.wikimedia.org/datasets/periodic/reports/metrics/browser/all_sites_by_os_and_browser.tsv"

//DeviceDetails SSLLabs clients cipher and protocol support information
var DeviceDetails = "https://api.ssllabs.com/api/v3/getClients"

func init() {

	//create data directories, if they don't exist
	if _, err := os.Stat(statsHome); os.IsNotExist(err) {
		if err2 := os.MkdirAll(statsHome, 0755); err2 != nil {
			log.Println("Could not create the path ", statsHome)
		}
	}

	if _, err := os.Stat(dataHome); os.IsNotExist(err) {
		if err2 := os.MkdirAll(dataHome, 0755); err2 != nil {
			log.Println("Could not create the path ", dataHome)
		}
	}
}

var (
	dateFormat       = "2006-01-02"
	home             = getHome()
	statsHome        = path.Join(home, "stats")
	dataHome         = path.Join(home, "data")
	today            = time.Now().Format(dateFormat)
	browserStatsData = path.Join(dataHome, fmt.Sprintf("browser-stats-%s.tsv", today))
	deviceCiphers    = path.Join(dataHome, fmt.Sprintf("device-ciphers-%s.json", today))
	jsonStatsOut     = path.Join(statsHome, "tls-stats-current.json")
)

func getHome() (h string) {
	h = ".tls-stats"
	if hh, err := homedir.Expand("~/.tls-stats"); err == nil {
		return hh
	}
	return
}

func download(filename, url string, force bool) (err error) {
	if _, err := os.Stat(filename); force || os.IsNotExist(err) {
		if resp, err := http.Get(url); err == nil {
			defer resp.Body.Close()
			if file, err := os.Create(filename); err == nil {
				defer file.Close()
				_, err = io.Copy(file, resp.Body)
			}
		}
	} else {
		return fmt.Errorf("Downloading file %s, which already exists. Use -f flag to force download", filename)
	}
	return
}

//DownloadData downloads data needed to calculate cipher support probabilities
func DownloadData(force bool) error {
	if err := download(browserStatsData, BrowserStats, force); err != nil {
		return err
	}
	if err := download(deviceCiphers, DeviceDetails, force); err != nil {
		return err
	}
	return nil
}
