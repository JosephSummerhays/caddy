/*
Ctmonitor will monitor certificate transparency logs and it will compare the caddy maintained certificate against the ones found in the logs and it will alert the user that there might have been an mississuance of the certificate.
*/
package caddytls

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
	"bytes"
	//"flag"
	//"reflect"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/mholt/caddy"

)/*
//I don't think that I will need this because I am building the map within
//the getCaddyCerts function.
func buildMap(certs [][]string, logs []Certificate) map[string][]Certificate {
	certs = certs
	//Creates certMap mapping a SAN to the corresponding certificate
	var certMap = make(map[string][]Certificate)

	//A double nested for loop that will go over each certificate and extract the SANs from each
	//certificate and map it back to the certificate for easier access.
	for i, certificate := range logs {
		i = i
		SANs := make([]string, len(certificate.X509Cert.DNSNames)) //makes a slice of type string the size of the SANs.
		SANs = certificate.X509Cert.DNSNames //assigns the SANs to the slice.
		//SANs = SANs
		//For each SAN, if it is found in the map it appends the certificate, otherwise adds a new entry to the map.
		for _, SAN := range SANs {
			if _, ok := certMap[SAN]; ok {
				certMap[SAN] = append(certMap[SAN], certificate)
			} else {
				certMap[SAN] = []Certificate{certificate}
			}
		}
	}
	return certMap
}*/


// CheckName will take in a string that will be used to look up a certificate in the map, the corresponding certificate that the name comes from
// and the certMap to check against, the certMap should be the certificates that caddy is monitoring.  Should append to a list of dangerous
// certificates if the corresponding certificate is not the same as the one that caddy contains.
func checkName(name string, cert ct.LogEntry, certMap map[string][]Certificate) bool {
	//so if I find the matching cert from the name, then I want to compare them to see if they are the same cert based off of their byte size.
	//for i,
	if matchingCert, ok := certMap[name]; ok {
		matchingCert = matchingCert
		//I would want to make a for loop and check all of the certificates for this slice.
		//replace the 0 in matchingCert to the iterator variable.
		if (bytes.Equal(cert.X509Cert.Raw, matchingCert[0].Certificate.Certificate[0])) {
			fmt.Println("The certs are the same")
			return true
		} else {
			fmt.Println("The certs are different, do not trust it")
		}
	} else {
		fmt.Println("The cert was not found")
	}
	return false
}



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
			fmt.Println(findPhonies(getMonitoredCerts(), getSANs(logUrl, i, i+sizeToGet)))
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

// GetCaddyCerts retrieves the certificates that caddy monitors and returns them as a map of
// their respective byte arrays casted as a string to the array of SAN
func getCaddyCerts() map[string][]Certificate {
	var caddyCerts = make (map[string][]Certificate)
	for _, inst := range caddy.Instances() {
		inst.StorageMu.RLock()
		certCache, ok := inst.Storage[CertCacheInstStorageKey].(*certificateCache)
		inst.StorageMu.RUnlock()
		if !ok || certCache == nil {
			continue
		}
		certCache.RLock()
		for _, certificate := range certCache.cache {//Here is where the map is being created.
			for _, eachName := range certificate.Names {
				if _, ok := caddyCerts[eachName]; ok {
					caddyCerts[eachName] = append(caddyCerts[eachName], certificate)
				} else {
					caddyCerts[eachName] = []Certificate{certificate}
				}
			}
		}
		certCache.RUnlock()//Create a slice from the map and return that as well, or just
		//make the map here instead of the slice.***************************************
	}
	return caddyCerts
}


// gets the certificates that caddy monitors and returns them as a map of
// their respective byte arrays casted as a string to the array of SAN
func getCaddyCertsWithInstance(instance caddy.Instance) map[string][]Certificate {
	var caddyCerts = make (map[string][]Certificate)
	for _, inst := range caddy.Instances() {
	//for _, inst := range instance {
		inst.StorageMu.RLock()
		certCache, ok := inst.Storage[CertCacheInstStorageKey].(*certificateCache)
		inst.StorageMu.RUnlock()
		if !ok || certCache == nil {
			continue
		}
		certCache.RLock()
		for _, certificate := range certCache.cache {//Here is where the map is being created.
			for _, eachName := range certificate.Names {
				if _, ok := caddyCerts[eachName]; ok {
					caddyCerts[eachName] = append(caddyCerts[eachName], certificate)
				} else {
					caddyCerts[eachName] = []Certificate{certificate}
				}
			}
		}
		certCache.RUnlock()//Create a slice from the map and return that as well, or just
		//make the map here instead of the slice.***************************************
	}
	return caddyCerts
}


func getSANs(url string, begin, end uint64) (certNames map[string][]string) {
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

// GetSAN retrieves the Subject Alternative Names from the given URI in the range [begin, end) and returns a slice of slices with all of the SANs for each
//certificate as well as a slice of all of the logs.
func getSAN(uri string, beginning, end int64) ([][]string, []ct.LogEntry) {
	//, retrievedEntries
	var opts jsonclient.Options
	httpClient := &http.Client{
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

	ctx := context.Background()
	logClient, err := client.New(uri, httpClient, opts)
	if err != nil { //Create the client
		log.Fatalf("logClient creation failed: %v", err)
	}
	entries, err := logClient.GetEntries(ctx, beginning, end)
	if err != nil { //Get the entries
		log.Fatal(err)
	}
	//fmt.Println("Entries type: ", reflect.TypeOf(entries))
	DNSAlternateNames := make([][]string, len(entries))

	for i := range DNSAlternateNames {
		DNSAlternateNames[i] = entries[i].X509Cert.DNSNames
	}
	//make a slice of slices so that we can access all of the DNSNames.
	return DNSAlternateNames, entries
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
