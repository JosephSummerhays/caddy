package caddytls

import "testing"

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
	}
	for _, c := range cases {
		output := looksSuspiciouslySimilar(c.s1, c.s2)
		if output != c.expected {
			t.Errorf("looksSuspicouslySimilarTo(%q,%q) == %v, but we expected %v", c.s1, c.s2, output, c.expected)
		}
	}

}

//I'm not sure if this test case is working... I didn't format it like the other one,
// and now it's not producing coverage percentage like the other one is. ask matt???
// or maybe try not to bother him too much and figure it out yourself.
func TestFindPhonies(t *testing.T) {
	var step uint64 = 10
	logUrl := "https://ct.googleapis.com/rocketeer"
	max := getSTHsize(logUrl)
	for i := max - 6*step; i < max-3*step; i += step {
		logTest := getSANs(logUrl, i, i+step)
		caddyTest := getSANs(logUrl, i+step/2, i+step/2)
		output1 := findPhonies(caddyTest, logTest)
		//this one should not find anything. although, the caddyTest
		//was drawn from logTest (and so it might seem they should match)
		//findPhonies should reject it because their bytes are the same.
		var caddyTest2 = make(map[string][]string)
		for key, value := range caddyTest {
			caddyTest2[key+"a"] = value //arbitrarily change key value
		}
		output2 := findPhonies(caddyTest2, logTest)

		caddyTest3 := getSANs(logUrl, i+2*step, i+2*step) //outside of range
		output3 := findPhonies(caddyTest3, logTest)

		if len(output1) > 0 {
			t.Errorf("incorrectly found %v in %v; the certs are the same", caddyTest, logTest)
		}
		if len(output2) <= 0 {
			t.Errorf("didn't find %v in %v", caddyTest2, logTest)
		}
		if len(output3) > 0 {
			t.Errorf("incorrectly found %v in %v; no such similarity", caddyTest3, logTest)
		}
	}
}
