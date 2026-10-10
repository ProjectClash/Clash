package clash

import (
	"fmt"
	"strings"

	"github.com/ProjectClash/Clash/component/geodata"
	georouter "github.com/ProjectClash/Clash/component/geodata/router"
	"github.com/ProjectClash/Clash/component/mmdb"
	"github.com/oschwald/maxminddb-golang"
	"google.golang.org/protobuf/proto"
)

const maximumGeodataResourceBytes int64 = geodata.MaxDatFileBytes

func ValidateGeodataForIOS(kind, format, path string) error {
	return bridgeSafeError(recoverAppCallError("ValidateGeodataForIOS", func() error { return validateGeodataForIOSUnguarded(kind, format, path) }))
}

func validateGeodataForIOSUnguarded(kind, format, path string) error {
	_, _, _, err := validateGeodataFile(kind, format, path)
	return bridgeSafeError(err)
}

func validateGeodataFile(kind, format, path string) (string, string, []byte, error) {
	kind = strings.ToLower(strings.TrimSpace(kind))
	format = strings.ToLower(strings.TrimSpace(format))
	if !((kind == "geoip" && (format == "mmdb" || format == "dat")) ||
		(kind == "geosite" && format == "dat") ||
		(kind == "asn" && format == "mmdb")) {
		return "", "", nil, fmt.Errorf("clash: unsupported geodata kind/format %q/%q", kind, format)
	}
	limit := maximumGeodataResourceBytes
	if format == "mmdb" {
		limit = mmdb.MaxDatabaseBytes
	}
	payload, err := readBoundedRegularFile(path, limit, "geodata")
	if err != nil {
		return "", "", nil, err
	}
	switch {
	case kind == "geoip" && format == "mmdb":
		err = validateMMDBGeodata(payload, false)
	case kind == "geoip" && format == "dat":
		err = validateGeoIPDat(payload)
	case kind == "geosite" && format == "dat":
		err = validateGeoSiteDat(payload)
	case kind == "asn" && format == "mmdb":
		err = validateMMDBGeodata(payload, true)
	}
	if err != nil {
		return "", "", nil, err
	}
	return kind, format, payload, nil
}

func validateMMDBGeodata(payload []byte, asn bool) error {
	if int64(len(payload)) > mmdb.MaxDatabaseBytes {
		return fmt.Errorf("clash: MMDB geodata is %d bytes, larger than the %d MiB the core opens",
			len(payload), mmdb.MaxDatabaseBytes>>20)
	}
	reader, err := maxminddb.FromBytes(payload)
	if err != nil {
		return fmt.Errorf("clash: invalid MMDB geodata: %w", err)
	}
	defer reader.Close()
	if reader.Metadata.NodeCount == 0 {
		return fmt.Errorf("clash: MMDB geodata has empty metadata")
	}
	if !databaseTypeIsUsable(reader.Metadata.DatabaseType) {
		kind := "GeoIP"
		if asn {
			kind = "ASN"
		}
		return fmt.Errorf("clash: %s MMDB declares no database type; the file is "+
			"most likely truncated or not an MMDB", kind)
	}
	return nil
}

func databaseTypeIsUsable(databaseType string) bool {
	return strings.TrimSpace(databaseType) != ""
}

func validateGeoIPDat(payload []byte) error {
	var list georouter.GeoIPList
	if err := proto.Unmarshal(payload, &list); err != nil {
		return fmt.Errorf("clash: invalid GeoIP.dat protobuf: %w", err)
	}
	for index, entry := range list.Entry {
		if strings.TrimSpace(entry.GetCountryCode()) == "" {
			return fmt.Errorf("clash: GeoIP.dat entry %d has a blank country code; "+
				"the memory-conservative loader iOS uses cannot scan past it", index)
		}
	}
	return nil
}

func validateGeoSiteDat(payload []byte) error {
	var list georouter.GeoSiteList
	if err := proto.Unmarshal(payload, &list); err != nil {
		return fmt.Errorf("clash: invalid GeoSite.dat protobuf: %w", err)
	}
	for index, entry := range list.Entry {
		if strings.TrimSpace(entry.GetCountryCode()) == "" {
			return fmt.Errorf("clash: GeoSite.dat entry %d has a blank country code; "+
				"the memory-conservative loader iOS uses cannot scan past it", index)
		}
	}
	return nil
}

func ValidateGeodataCodesForIOS(kind, format, path, codes string) error {
	normalizedKind, normalizedFormat, payload, err := validateGeodataFile(kind, format, path)
	if err != nil {
		return bridgeSafeError(err)
	}
	wanted := normalizeGeodataCodes(codes)
	if len(wanted) == 0 || normalizedFormat != "dat" {
		return nil
	}
	if normalizedKind == "geoip" {
		return bridgeSafeError(validateGeoIPDatCodes(payload, wanted))
	}
	return bridgeSafeError(validateGeoSiteDatCodes(payload, wanted))
}

func normalizeGeodataCodes(codes string) []string {
	fields := strings.FieldsFunc(codes, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
	normalized := make([]string, 0, len(fields))
	for _, field := range fields {
		code := strings.TrimSpace(field)
		code = strings.TrimPrefix(code, "!")
		if attribute := strings.IndexByte(code, '@'); attribute >= 0 {
			code = code[:attribute]
		}
		code = strings.TrimSpace(strings.ToLower(code))
		if code != "" {
			normalized = append(normalized, code)
		}
	}
	return normalized
}

func validateGeoIPDatCodes(payload []byte, codes []string) error {
	var list georouter.GeoIPList
	if err := proto.Unmarshal(payload, &list); err != nil {
		return fmt.Errorf("clash: invalid GeoIP.dat protobuf: %w", err)
	}
	for _, code := range codes {
		found := false
		for _, entry := range list.Entry {
			if !strings.EqualFold(entry.GetCountryCode(), code) {
				continue
			}
			found = true
			if _, err := georouter.NewGeoIPMatcher(entry.GetCidr()); err != nil {
				return fmt.Errorf("clash: GeoIP.dat country %q does not load: %w", code, err)
			}
			break
		}
		if !found {
			return fmt.Errorf("clash: GeoIP.dat has no country %q", code)
		}
	}
	return nil
}

func validateGeoSiteDatCodes(payload []byte, codes []string) error {
	var list georouter.GeoSiteList
	if err := proto.Unmarshal(payload, &list); err != nil {
		return fmt.Errorf("clash: invalid GeoSite.dat protobuf: %w", err)
	}
	for _, code := range codes {
		found := false
		for _, entry := range list.Entry {
			if !strings.EqualFold(entry.GetCountryCode(), code) {
				continue
			}
			found = true
			_, succinctErr := georouter.NewSuccinctMatcherGroup(entry.GetDomain())
			if succinctErr != nil {
				if _, mphErr := georouter.NewMphMatcherGroup(entry.GetDomain()); mphErr != nil {
					return fmt.Errorf("clash: GeoSite.dat list %q does not load under either matcher: %v (succinct); %v (mph)", code, succinctErr, mphErr)
				}
			}
			break
		}
		if !found {
			return fmt.Errorf("clash: GeoSite.dat has no list %q", code)
		}
	}
	return nil
}
