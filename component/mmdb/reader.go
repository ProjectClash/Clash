package mmdb

import (
	"fmt"
	"net"
	"strings"

	"github.com/ProjectClash/Clash/log"
	"github.com/oschwald/maxminddb-golang"
)

type geoip2Country struct {
	Country struct {
		IsoCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

type IPReader struct {
	reader *maxminddb.Reader
	databaseType
	holder *readerHolder
}

type ASNReader struct {
	reader *maxminddb.Reader
	holder *readerHolder
}

type GeoLite2 struct {
	AutonomousSystemNumber       uint32 `maxminddb:"autonomous_system_number"`
	AutonomousSystemOrganization string `maxminddb:"autonomous_system_organization"`
}

type IPInfo struct {
	ASN  string `maxminddb:"asn"`
	Name string `maxminddb:"name"`
}

func (r IPReader) LookupCode(ipAddress net.IP) []string {
	if r.holder != nil {
		s := r.holder.acquire()
		if s == nil {
			return []string{}
		}
		defer r.holder.release(s)
		return lookupCode(s.reader, s.databaseType, ipAddress)
	}
	if r.reader == nil {
		return []string{}
	}
	return lookupCode(r.reader, r.databaseType, ipAddress)
}

func lookupCode(reader *maxminddb.Reader, kind databaseType, ipAddress net.IP) []string {
	return decodeCodes(kind, func(result any) error { return reader.Lookup(ipAddress, result) })
}

func decodeCodes(kind databaseType, decode func(result any) error) []string {
	switch kind {
	case typeMaxmind:
		var country geoip2Country
		_ = decode(&country)
		if country.Country.IsoCode == "" {
			return []string{}
		}
		return []string{strings.ToLower(country.Country.IsoCode)}

	case typeSing:
		var code string
		_ = decode(&code)
		if code == "" {
			return []string{}
		}
		return []string{code}

	case typeMetaV0:
		var record any
		_ = decode(&record)
		switch record := record.(type) {
		case string:
			return []string{record}
		case []any: // lookup returned type of slice is []any
			result := make([]string, 0, len(record))
			for _, item := range record {
				if code, ok := item.(string); ok {
					result = append(result, code)
				}
			}
			return result
		}
		return []string{}

	default:
		log.Warnln("Unknown geoip database type: %d; GEOIP rules will not match", kind)
		return []string{}
	}
}

func (r ASNReader) LookupASN(ip net.IP) (string, string) {
	if r.holder != nil {
		s := r.holder.acquire()
		if s == nil {
			return "", ""
		}
		defer r.holder.release(s)
		return lookupASN(s.reader, ip)
	}
	if r.reader == nil {
		return "", ""
	}
	return lookupASN(r.reader, ip)
}

func lookupASN(reader *maxminddb.Reader, ip net.IP) (string, string) {
	asn, name, supported := decodeASN(reader.Metadata.DatabaseType, func(result any) error { return reader.Lookup(ip, result) })
	if !supported {
		log.Warnln("Unsupported ASN type: %s", reader.Metadata.DatabaseType)
	}
	return asn, name
}

func decodeASN(databaseType string, decode func(result any) error) (asn, name string, supported bool) {
	switch databaseType {
	case "GeoLite2-ASN", "DBIP-ASN-Lite (compat=GeoLite2-ASN)":
		var result GeoLite2
		_ = decode(&result)
		return fmt.Sprint(result.AutonomousSystemNumber), result.AutonomousSystemOrganization, true
	case "ipinfo generic_asn_free.mmdb":
		var result IPInfo
		_ = decode(&result)
		if len(result.ASN) < 2 || !strings.HasPrefix(result.ASN, "AS") {
			return "", result.Name, true
		}
		return result.ASN[2:], result.Name, true
	}
	return "", "", false
}
