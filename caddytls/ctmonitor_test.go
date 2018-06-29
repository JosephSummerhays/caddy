package caddytls

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"testing"
)

func TestLooksSuspiciouslySimilar(t *testing.T) {
	cases := []struct {
		s1, s2   string
		expected bool
	}{
		{"ct.googleapis.com", "ct.Google-apis.com", true},
		{"OneFluffyBunny.net", "onefluffy-bunny.org", true},
		{"", "testwithnothing.org", false},
		{"testwithnothing.net", "", false},
		{"", "", false},
		{"twoveryUnsimilar.com", "domainNames.org", false},
		{"www.apple.com", "www.orange.net", false},
		{"apple.com", "apple.com.thisisa.funnylookin.setof.subdomains.co", true},
		{"apple.com.this.is.a.funnylookin.setof.subdomains.co", "apple.com", true},
		{"www.apple.com", "apple.com.this.is.a.funnylookin.setof.subdomains.co", true},
		{"apple.com", "www.apple.com", true},
		{"apple.com", "www.apple.com.this.is.a.funnylookin.setof.subdomains.co", true},
		{"*.byu.edu", "wildcard.byu.edu", true},
		{"wildcard.byu.edu", "*.byu.edu", true},
		{"wildcard.withsubdomain.byu.edu", "*.byu.edu", true},
		{"*.byu.edu", "wildcard.withsubdomain.byu.edu", true},
		{"youtube.com", "yewtube.com", true},
		{"youtube.com", "youtubee.com", true},
		{"youtube.com", "youtub.com", true},
		{"youtube.com", "youtube.co", true},
	}
	for _, c := range cases {
		output := looksSuspiciouslySimilar(c.s1, c.s2)
		if output != c.expected {
			t.Errorf("looksSuspicouslySimilarTo(%q,%q) == %v, but we expected %v", c.s1, c.s2, output, c.expected)
		}
	}
}

func delete_empty(s []string) (r []string) {
	for _, str := range s {
		if str != "" {
			r = append(r, str)
		}
	}
	return r
}

func TestFindPhoniesFromFile(t *testing.T) {
	fileName := "hostAndSANs.csv"
	file, err := os.Open(fileName)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	reader := csv.NewReader(bufio.NewReader(file))
	line, err := reader.Read()
	line = delete_empty(line)
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}
	totNumerator := 0
	totDenominator := 0
	//for err != io.EOF {
	for i := 0; i < 2; i++ {
		var certArray, phoniesArray []string
		certArray = line[1:]
		phoniesArray = append(phoniesArray, line[0])
		line, err = reader.Read()
		line = delete_empty(line)
		for len(line) == 1 {
			phoniesArray = append(phoniesArray, line[0])
			line, err = reader.Read()
			line = delete_empty(line)
			if err != nil && err != io.EOF {
				t.Fatal(err)
			}
		}
		caddyMap := make(map[string][]string)
		phoniesMap := make(map[string][]string)
		caddyMap["a"] = certArray
		phoniesMap["b"] = phoniesArray
		foundPhonies := findPhonies(caddyMap, phoniesMap)
		fmt.Printf("found %v out of %v \n", foundPhonies, phoniesArray)
		fmt.Printf("that's %g%%\n\n", (float32(len(foundPhonies))/float32(len(phoniesArray)))*100.0)
		totNumerator += len(foundPhonies)
		totDenominator += len(phoniesArray)
	}
	fmt.Printf("total accuracy is %g%%", (float32(totNumerator)/float32(totDenominator))*100)

}

//I'm not sure if this test case is working... I didn't format it like the other one,
// and now it's not producing coverage percentage like the other one is. ask matt???
// or maybe try not to bother him too much and figure it out yourself.
// func TestFindPhonies(t *testing.T) {
// 	var step uint64 = 10
// 	logUrl := "https://ct.googleapis.com/rocketeer"
// 	max := getSTHsize(logUrl)
// 	for i := max - 6*step; i < max-3*step; i += step {
// 		logTest := getSANs(logUrl, i, i+step)
// 		caddyTest := getSANs(logUrl, i+step/2, i+step/2)
// 		output1 := findPhonies(caddyTest, logTest)
// 		//this one should not find anything. although, the caddyTest
// 		//was drawn from logTest (and so it might seem they should match)
// 		//findPhonies should reject it because their bytes are the same.
// 		var caddyTest2 = make(map[string][]string)
// 		for key, value := range caddyTest {
// 			caddyTest2[key+"a"] = value //arbitrarily change key value
// 		}
// 		output2 := findPhonies(caddyTest2, logTest)
//
// 		caddyTest3 := getSANs(logUrl, i+2*step, i+2*step) //outside of range
// 		output3 := findPhonies(caddyTest3, logTest)
//
// 		if len(output1) > 0 {
// 			t.Errorf("incorrectly found %v in %v; the certs are the same", caddyTest, logTest)
// 		}
// 		if len(output2) <= 0 {
// 			t.Errorf("didn't find %v in %v", caddyTest2, logTest)
// 		}
// 		if len(output3) > 0 {
// 			t.Errorf("incorrectly found %v in %v; no such similarity", caddyTest3, logTest)
// 		}
// 	}
// }
