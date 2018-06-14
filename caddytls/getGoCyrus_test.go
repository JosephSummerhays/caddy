package caddytls

import (
	"flag"
	"fmt"
	"testing"

	"github.com/mholt/caddy"
)

func TestGetGoCyrusCert(t *testing.T) {
	APIPath := flag.String("api", "https://ct.googleapis.com/rocketeer", "desired api to query.")
	beginIndex := flag.Int64("begin", 302990629, "The start index that you want to query")
	endIndex := flag.Int64("end", 302990629, "The end index that you want to query, non-inclusive")
	flag.Parse()

	inst := &caddy.Instance{
		Storage: make(map[interface{}]interface{}),
	}
	//create a new config from our instance
	cfg := NewConfig(inst)
	err := cfg.cacheUnmanagedCertificatePEMFile("gocyrusCert/.caddy/acme/acme-v02.api.letsencrypt.org/sites/gocyrus.net/gocyrus.net.crt", "gocyrusCert/.caddy/acme/acme-v02.api.letsencrypt.org/sites/gocyrus.net/gocyrus.net.key")
	if err != nil {
		fmt.Println("There was an error caching the UnmanagedCertificatePEMFile")
		t.Fatal(err)
	} else {
		fmt.Println("Function exited successfuly, no error for cfg.cacheUnmanagedCertificate.")
	}
	//caddyCertMap := getCaddyCerts()

	//Trying to just manually create the map instead of going through our function.

	var caddyCerts = make (map[string][]Certificate)
	//for _, inst := range caddy.Instances() {
		inst.StorageMu.RLock()
		certCache, ok := inst.Storage[CertCacheInstStorageKey].(*certificateCache)
		inst.StorageMu.RUnlock()
		if !ok || certCache == nil {
			fmt.Println("!ok or certCache == nil")//continue
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
	//}
	
	//End attempt
	
	fmt.Println("inst storage size: ", len(inst.Storage))
	//caddyCertMap := getCaddyCertsWithInstance(inst)
	fmt.Println("caddyCertMap size: ", len(caddyCerts))
	for _, cert := range caddyCerts {
		delimiter := ""
		for _, name := range cert[0].Names {
			fmt.Print(delimiter, name)
			delimiter = ", "
		}
	}
	certMap := getMonitoredCerts()
	fmt.Println("certMap size: ", len(certMap))
	for _, cert := range certMap {
		delimiter := ""
		for _, name := range cert {
			fmt.Print(delimiter, name)
			delimiter = ", "
		}
	}
	_, gocyrusCert := getSAN(*APIPath, *beginIndex, *endIndex)
	fmt.Println("The key lookup name is: ", gocyrusCert[0].X509Cert.DNSNames[0])
	if !checkName(gocyrusCert[0].X509Cert.DNSNames[0], gocyrusCert[0], caddyCerts) {
		t.Error("Could not find the gocyrus.net cert, or they did not match.")
	}

	fmt.Println("Checking the lets encrypt and the cpanel certs.")
	_, gocyrusCert = getSAN(*APIPath, 296334571, 296334571)
	fmt.Println("The key lookup name is: ", gocyrusCert[0].X509Cert.DNSNames[0])
	if checkName(gocyrusCert[0].X509Cert.DNSNames[0], gocyrusCert[0], caddyCerts) {
		t.Error("Did not differentiate between the cpanel and lets encrypt's cert.")
	}

		_, gocyrusCert = getSAN(*APIPath, *beginIndex + 1, *endIndex + 1)
	fmt.Println("The key lookup name is: ", gocyrusCert[0].X509Cert.DNSNames[0])
	if checkName("gocyrus.net", gocyrusCert[0], caddyCerts) {
		t.Error("Accepted the wrong certificate matched to gocyrus.net")
	}
	
/* //if you run this one, it will tell you that you have a bad request.
	_, gocyrusCert = getSAN(*APIPath, *beginIndex + 1, *endIndex + 1)
	fmt.Println("The key lookup name is: ", gocyrusCert[0].X509Cert.DNSNames[0])
	if checkName(gocyrusCert[0].X509Cert.DNSNames[0], gocyrusCert[0], caddyCerts) {
		t.Error("Failed to distinguish between certificates.")
	}
	*/	
}
