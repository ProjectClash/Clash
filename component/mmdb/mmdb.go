package mmdb

import (
	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/log"
)

type databaseType = uint8

const (
	typeMaxmind databaseType = iota
	typeSing
	typeMetaV0
)

var (
	ipPublisher  = newPublisher("MMDB", func() string { return C.Path.MMDB() })
	asnPublisher = newPublisher("ASN", func() string { return C.Path.ASN() })
)

func (r IPReader) available() bool  { return r.holder.available() || r.reader != nil }
func (r ASNReader) available() bool { return r.holder.available() || r.reader != nil }

func (r IPReader) Available() bool  { return r.available() }
func (r ASNReader) Available() bool { return r.available() }

func LoadFromBytes(buffer []byte) {
	if err := ipPublisher.Adopt(buffer); err != nil {
		log.Errorln("Can't load mmdb: %s; GEOIP rules will not match", err.Error())
	}
}

func Verify(path string) bool {
	instance, err := openDatabaseFile(path)
	if err == nil {
		instance.Close()
	}
	return err == nil
}

func IPInstance() IPReader {
	seedFromDisk(ipPublisher, "MMDB", "GEOIP rules")
	return IPReader{holder: ipPublisher.holder}
}

func ASNInstance() ASNReader {
	seedFromDisk(asnPublisher, "ASN", "IP-ASN rules")
	return ASNReader{holder: asnPublisher.holder}
}

func seedFromDisk(p *publisher, name, rules string) {
	if err := p.EnsureSeeded(); err != nil {
		log.Errorln("Can't load %s: %s; %s will not match", name, err.Error(), rules)
	}
}

func reloadFromDisk(p *publisher, name, rules string) {
	log.Infoln("Load %s file: %s", name, p.path())
	if err := p.Reopen(); err != nil {
		log.Errorln("Can't load %s: %s; %s will not match", name, err.Error(), rules)
	}
}

func ReloadIP() {
	reloadFromDisk(ipPublisher, "MMDB", "GEOIP rules")
}

func ReloadASN() {
	reloadFromDisk(asnPublisher, "ASN", "IP-ASN rules")
}

func PublishIP(data []byte) error { return ipPublisher.Publish(data) }

func PublishASN(data []byte) error { return asnPublisher.Publish(data) }
