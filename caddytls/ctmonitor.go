package caddytls

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/mholt/caddy"
)

func init() {
	go monitorstuff()
}

// Periodically checks the log for new entries, checking each on for bad certs
// TO-DO change to checking ALL logs, rather than just one.
func monitorstuff() {
	// it's common for ct logs to limit queries to 64 certificates
	const stepSize uint64 = 64                         // TO_DO dynamically create step size based on api responses
	var logUrl = "https://ct.googleapis.com/rocketeer" // TO_DO change this to a map of ct log domains to initialSizes of those logs
	initialSize := getSTHsize(logUrl)
	for ; true; time.Sleep(5 * time.Minute) { // indefinitely repeat, every five minutes
		newSize := getSTHsize(logUrl)
		for i := initialSize; i <= newSize; i += stepSize {
			sizeToGet := stepSize
			if i+stepSize > newSize { //if we've gone beyond the newest entry in the log
				sizeToGet = uint64(newSize - i)
			}
			fmt.Println(findPhonies(getMonitoredCerts(), getSAN(logUrl, i, i+sizeToGet)))
			//now that we've found 'em, what do we do with them????
		}
		initialSize = newSize //so that we don't rescan old entries
	}
}

// gets the certificates that caddy monitors and returns them as a map of
// their respective byte arrays casted as a string to the array of SAN
func getMonitoredCerts() (monitoredCerts map[string][]string) {
	for _, inst := range caddy.Instances() {
		inst.StorageMu.RLock()
		certCache, ok := inst.Storage[CertCacheInstStorageKey].(*certificateCache)
		inst.StorageMu.RUnlock()
		if !ok || certCache == nil {
			continue
		}
		certCache.RLock()
		for _, cert := range certCache.cache {
			monitoredCerts[string(cert.Certificate.Certificate[0])] = cert.Names
		}
		certCache.RUnlock()
	}
	return
}

func getSAN(url string, begin, end uint64) (certNames map[string][]string) {
	certNames = make(map[string][]string)
	var opts jsonclient.Options
	httpClient := &http.Client{ //possibly refactor this code so this is a constant in the file?
		Timeout: 10 * time.Second, //I'm not sure if that's syntactically possible...
		Transport: &http.Transport{
			TLSHandshakeTimeout:   30 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			MaxIdleConnsPerHost:   10,
			DisableKeepAlives:     false,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}

	ctx := context.Background() //same possible refactorization?
	logClient, err := client.New(url, httpClient, opts)
	if err != nil {
		log.Fatalf("AAAAAAGH! %v", err)
	}
	entries, err := logClient.GetEntries(ctx, int64(begin), int64(end))
	if err != nil {
		log.Fatal(err)
	}
	for _, entry := range entries {
		certNames[string(entry.X509Cert.Raw)] = entry.X509Cert.DNSNames //creates map from raw bytes (cast as string) to SAN
	}
	return
}

//Pretty self explanitory. It gets the size of the Signed Tree Head of the ct log found at the given url
// only enter the log's domain and subfolder. don't enter the specifics of the api endpoint. The function
// will append that.
func getSTHsize(url string) uint64 {
	var opts jsonclient.Options
	ctx := context.Background()
	httpClient := &http.Client{ //possibly refactor this code so this is a constant in the file?
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSHandshakeTimeout:   30 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			MaxIdleConnsPerHost:   10,
			DisableKeepAlives:     false,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
	logClient, err := client.New(url, httpClient, opts)
	if err != nil {
		log.Fatal(err)
	}
	sth, err := logClient.GetSTH(ctx)
	if err != nil {
		log.Fatal(err)
	}
	return sth.TreeSize
}

// removes the top level domain, any dashes, and puts it into lower case.
//techinically speaking, all domain names are case insensitive, but I wasn't
// sure if ct Logs were required to maintain that standard.
func simplifyName(name string) string {
	if len(name) == 0 {
		return name
	}
	return strings.ToLower(strings.Replace(name[0:strings.LastIndex(name, ".")], "-", "", -1)) //removes the top level domain, puts the url into lower case, removes dashes
}

// returns true if s1 looks suspiciouslySimilar to s2.
// if either string is empty it should return false.
// currently not passing all test cases. we'll develope a more robust version later.
// if you want to edit the function, just comment this out and create your own of the same
// signature. see if you can pass my test cases.
func looksSuspiciouslySimilar(s1, s2 string) bool {
	return strings.Contains(simplifyName(s1), simplifyName(s2))
}

func findPhonies(caddyCerts, logCerts map[string][]string) (phonies []string) {
	for caddyKey, caddyNames := range caddyCerts {
		for logKey, logNames := range logCerts {
			//Possible optimization here: edit logNames and caddyNames to remove redundant SAN
			for _, caddyName := range caddyNames {
				for _, logName := range logNames {
					if looksSuspiciouslySimilar(logName, caddyName) {
						if caddyKey != logKey { // perhaps we should put this if statement around for loops #3&4? I'm not sure which will be more efficient...
							phonies = append(phonies, logName)
						}
					}
				}
			}
		}
	}
	return
}
