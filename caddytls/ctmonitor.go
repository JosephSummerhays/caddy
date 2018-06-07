package caddytls

import (
	"fmt"

	"github.com/mholt/caddy"
)

func getMonitoredCerts() (monitoredCerts []string) {
	for _, inst := range caddy.Instances() {
		inst.StorageMu.RLock()
		certCache, ok := inst.Storage[CertCacheInstStorageKey].(*certificateCache)
		inst.StorageMu.RUnlock()
		if !ok || certCache == nil {
			continue
		}
		certCache.RLock()
		for _, cert := range certCache.cache {
			fmt.Println(cert.Names)
			monitoredCerts = append(monitoredCerts, cert.Names...)
		}
		certCache.RUnlock()
	}
	return
}
