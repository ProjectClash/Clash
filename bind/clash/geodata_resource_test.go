package clash

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	georouter "github.com/ProjectClash/Clash/component/geodata/router"
	"github.com/ProjectClash/Clash/component/mmdb"
	"google.golang.org/protobuf/proto"
)

func writeGeodataFixture(t *testing.T, payload []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "resource")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestValidateGeoIPDatForIOS(t *testing.T) {
	payload, err := proto.Marshal(&georouter.GeoIPList{Entry: []*georouter.GeoIP{{
		CountryCode: "CN",
		Cidr: []*georouter.CIDR{{
			Ip:     []byte{1, 1, 1, 0},
			Prefix: 24,
		}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateGeodataForIOS("geoip", "dat", writeGeodataFixture(t, payload)); err != nil {
		t.Fatalf("valid GeoIP.dat rejected: %v", err)
	}
}

func TestValidateGeoSiteDatForIOS(t *testing.T) {
	payload, err := proto.Marshal(&georouter.GeoSiteList{Entry: []*georouter.GeoSite{{
		CountryCode: "private",
		Domain: []*georouter.Domain{{
			Type:  georouter.Domain_Domain,
			Value: "example.com",
		}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateGeodataForIOS("geosite", "dat", writeGeodataFixture(t, payload)); err != nil {
		t.Fatalf("valid GeoSite.dat rejected: %v", err)
	}
}

func TestSupportedGeoIPDatabaseTypeMirrorsUpstreamTypeMaxmind(t *testing.T) {
	for _, dbType := range []string{
		"GeoIP2-Enterprise",
		"GeoIP2-Precision-Enterprise",
		"DBIP-Location-ISP (compat=Enterprise)",
		"a-custom-typed-geoip-db",
		"sing-geoip",
		"Meta-geoip0",
		"GeoLite2-Country",
		"GeoIP2-City",
	} {
		if !databaseTypeIsUsable(dbType) {
			t.Errorf("GeoIP MMDB type %q must be accepted (upstream typeMaxmind loads it)", dbType)
		}
	}
	for _, empty := range []string{"", "   "} {
		if databaseTypeIsUsable(empty) {
			t.Errorf("empty GeoIP MMDB type %q must be rejected", empty)
		}
	}
}

func TestValidateGeodataRejectsMalformedAndMismatchedResources(t *testing.T) {
	path := writeGeodataFixture(t, []byte("not geodata"))
	for _, test := range []struct {
		kind, format string
	}{
		{"geoip", "dat"},
		{"geoip", "mmdb"},
		{"geosite", "dat"},
		{"asn", "mmdb"},
		{"asn", "dat"},
	} {
		if err := ValidateGeodataForIOS(test.kind, test.format, path); err == nil {
			t.Errorf("malformed %s/%s resource accepted", test.kind, test.format)
		}
	}
}

func TestValidateGeodataRejectsSymlinkAndOversizedFile(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := ValidateGeodataForIOS("geoip", "dat", link); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("symlink was not rejected: %v", err)
	}

	oversized := filepath.Join(directory, "oversized")
	file, err := os.Create(oversized)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maximumGeodataResourceBytes + 1); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ValidateGeodataForIOS("geoip", "dat", oversized); err == nil || !strings.Contains(err.Error(), "size") {
		t.Fatalf("oversized file was not rejected: %v", err)
	}
}

func TestASNDatabaseTypeIsNotAnAllowList(t *testing.T) {
	for _, databaseType := range []string{
		"DBIP-ASN-Lite",
		"GeoIP2-ISP",
		"ipinfo standard_asn.mmdb",
		"GeoLite2-ASN-CSV",
	} {
		if !databaseTypeIsUsable(databaseType) {
			t.Errorf("rejected %q, which upstream loads and reads (it warns and "+
				"returns empty for the lookup, it does not refuse the database)",
				databaseType)
		}
	}
}

func TestConcatenatedDatIsNotADuplicateCodeError(t *testing.T) {
	marshal := func(code, domain string) []byte {
		list := &georouter.GeoSiteList{Entry: []*georouter.GeoSite{{
			CountryCode: code,
			Domain: []*georouter.Domain{
				{Type: georouter.Domain_Domain, Value: domain},
			},
		}}}
		encoded, err := proto.Marshal(list)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	merged := append(marshal("cn", "example.cn"), marshal("cn", "private.example")...)

	var parsed georouter.GeoSiteList
	if err := proto.Unmarshal(merged, &parsed); err != nil {
		t.Fatalf("fixture does not reproduce the shape: %v", err)
	}
	if len(parsed.Entry) != 2 {
		t.Fatalf("fixture does not reproduce the shape: %d entries", len(parsed.Entry))
	}

	if err := validateGeoSiteDat(merged); err != nil {
		t.Fatalf("rejected a merged GeoSite.dat that upstream resolves: %v", err)
	}
}

func TestConcatenatedGeoIPDatIsNotADuplicateCodeError(t *testing.T) {
	marshal := func(code string, ip []byte, prefix uint32) []byte {
		list := &georouter.GeoIPList{Entry: []*georouter.GeoIP{{
			CountryCode: code,
			Cidr:        []*georouter.CIDR{{Ip: ip, Prefix: prefix}},
		}}}
		encoded, err := proto.Marshal(list)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	merged := append(
		marshal("cn", []byte{1, 0, 0, 0}, 8),
		marshal("cn", []byte{203, 0, 113, 0}, 24)...,
	)
	if err := validateGeoIPDat(merged); err != nil {
		t.Fatalf("rejected a merged GeoIP.dat that upstream resolves: %v", err)
	}
}

func TestBlankCountryCodeStaysRejected(t *testing.T) {
	blank, err := proto.Marshal(&georouter.GeoIPList{Entry: []*georouter.GeoIP{
		{CountryCode: "cn", Cidr: []*georouter.CIDR{{Ip: []byte{1, 0, 0, 0}, Prefix: 8}}},
		{CountryCode: "", Cidr: []*georouter.CIDR{{Ip: []byte{9, 0, 0, 0}, Prefix: 8}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := validateGeoIPDat(blank); err == nil {
		t.Fatal("a blank CountryCode was accepted; memconservative aborts on it and " +
			"falls back to whole-file proto.Unmarshal inside the extension")
	}

	site, err := proto.Marshal(&georouter.GeoSiteList{Entry: []*georouter.GeoSite{
		{CountryCode: "", Domain: []*georouter.Domain{
			{Type: georouter.Domain_Domain, Value: "example.com"},
		}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := validateGeoSiteDat(site); err == nil {
		t.Fatal("a blank CountryCode was accepted in GeoSite.dat")
	}
}

func TestEmptyCategoriesAreAcceptedNotRejected(t *testing.T) {
	ip, err := proto.Marshal(&georouter.GeoIPList{Entry: []*georouter.GeoIP{
		{CountryCode: "cn", Cidr: []*georouter.CIDR{{Ip: []byte{1, 0, 0, 0}, Prefix: 8}}},
		{CountryCode: "xx"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := validateGeoIPDat(ip); err != nil {
		t.Errorf("a GeoIP entry with no CIDRs was rejected: %v", err)
	}

	site, err := proto.Marshal(&georouter.GeoSiteList{Entry: []*georouter.GeoSite{
		{CountryCode: "cn", Domain: []*georouter.Domain{
			{Type: georouter.Domain_Domain, Value: "example.cn"},
		}},
		{CountryCode: "xx"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := validateGeoSiteDat(site); err != nil {
		t.Errorf("a GeoSite category with no domains was rejected: %v", err)
	}
}

func TestPerEntryDefectsDoNotRefuseTheWholeFile(t *testing.T) {
	site := mustMarshalGeodata(t, &georouter.GeoSiteList{Entry: []*georouter.GeoSite{
		{CountryCode: "cn", Domain: []*georouter.Domain{
			{Type: georouter.Domain_Domain, Value: "example.cn"},
		}},
		{CountryCode: "broken", Domain: []*georouter.Domain{
			{Type: georouter.Domain_Type(99), Value: "example.invalid"},
			{Type: georouter.Domain_Full, Value: "   "},
		}},
	}})
	if err := ValidateGeodataForIOS("geosite", "dat", writeGeodataFixture(t, site)); err != nil {
		t.Errorf("one bad category refused the whole GeoSite.dat: %v", err)
	}

	ip := mustMarshalGeodata(t, &georouter.GeoIPList{Entry: []*georouter.GeoIP{
		{CountryCode: "cn", Cidr: []*georouter.CIDR{{Ip: []byte{1, 0, 0, 0}, Prefix: 8}}},
		{CountryCode: "broken", Cidr: []*georouter.CIDR{
			{Ip: []byte{1, 2, 3}, Prefix: 8},
		}},
	}})
	if err := ValidateGeodataForIOS("geoip", "dat", writeGeodataFixture(t, ip)); err != nil {
		t.Errorf("one bad category refused the whole GeoIP.dat: %v", err)
	}

	if err := validateGeoIPDat(mustMarshalGeodata(t, &georouter.GeoIPList{})); err != nil {
		t.Errorf("a GeoIP.dat carrying no entries was refused: %v", err)
	}
	if err := validateGeoSiteDat(mustMarshalGeodata(t, &georouter.GeoSiteList{})); err != nil {
		t.Errorf("a GeoSite.dat carrying no entries was refused: %v", err)
	}

	if err := ValidateGeodataForIOS("geoip", "dat", writeGeodataFixture(t, nil)); err == nil {
		t.Error("a zero-length file was accepted; the read-path guard is gone")
	}
}

func TestScopedValidationJudgesOnlyTheRequestedCodes(t *testing.T) {
	ip := writeGeodataFixture(t, mustMarshalGeodata(t, &georouter.GeoIPList{Entry: []*georouter.GeoIP{
		{CountryCode: "cn", Cidr: []*georouter.CIDR{{Ip: []byte{1, 0, 0, 0}, Prefix: 8}}},
		{CountryCode: "us", Cidr: []*georouter.CIDR{{Ip: []byte{1, 2, 3}, Prefix: 8}}},
	}}))

	if err := ValidateGeodataCodesForIOS("geoip", "dat", ip, "cn"); err != nil {
		t.Errorf("a good code was failed by a bad sibling: %v", err)
	}
	err := ValidateGeodataCodesForIOS("geoip", "dat", ip, "cn,us")
	if err == nil {
		t.Fatal("a code that cannot build its matcher was accepted")
	}
	if !strings.Contains(err.Error(), `"us"`) {
		t.Errorf("the error does not name the code that failed: %v", err)
	}

	site := writeGeodataFixture(t, mustMarshalGeodata(t, &georouter.GeoSiteList{Entry: []*georouter.GeoSite{
		{CountryCode: "cn", Domain: []*georouter.Domain{{Type: georouter.Domain_Domain, Value: "example.cn"}}},
	}}))
	for _, code := range []string{"cn", "CN", "!cn", "cn@ads", "!CN@ads", " cn "} {
		if err := ValidateGeodataCodesForIOS("geosite", "dat", site, code); err != nil {
			t.Errorf("code %q was not normalized the way upstream normalizes it: %v", code, err)
		}
	}

	if err := ValidateGeodataCodesForIOS("geosite", "dat", site, "nosuchcode"); err == nil {
		t.Error("a code the file does not carry was accepted")
	}

	mixed := writeGeodataFixture(t, mustMarshalGeodata(t, &georouter.GeoSiteList{Entry: []*georouter.GeoSite{
		{CountryCode: "skipped", Domain: []*georouter.Domain{
			{Type: georouter.Domain_Type(99), Value: "example.invalid"},
		}},
		{CountryCode: "broken", Domain: []*georouter.Domain{
			{Type: georouter.Domain_Regex, Value: "("},
		}},
	}}))
	if err := ValidateGeodataCodesForIOS("geosite", "dat", mixed, "skipped"); err != nil {
		t.Errorf("a domain type the matcher skips was treated as a failure: %v", err)
	}
	if err := ValidateGeodataCodesForIOS("geosite", "dat", mixed, "broken"); err == nil {
		t.Error("a value no matcher accepts was accepted")
	}
	if err := ValidateGeodataCodesForIOS("geoip", "dat", ip, "  "); err != nil {
		t.Errorf("naming no codes still judged the file: %v", err)
	}
}

func mustMarshalGeodata(t *testing.T, message proto.Message) []byte {
	t.Helper()
	encoded, err := proto.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestScopedValidationAcceptsWhatEitherRuntimeMatcherAccepts(t *testing.T) {
	site := writeGeodataFixture(t, mustMarshalGeodata(t, &georouter.GeoSiteList{Entry: []*georouter.GeoSite{
		{CountryCode: "succinct-only", Domain: []*georouter.Domain{
			{Type: georouter.Domain_Type(99), Value: "example.invalid"},
		}},
		{CountryCode: "mph-only", Domain: []*georouter.Domain{
			{Type: georouter.Domain_Full, Value: "   "},
		}},
		{CountryCode: "neither", Domain: []*georouter.Domain{
			{Type: georouter.Domain_Regex, Value: "("},
		}},
	}}))
	if err := ValidateGeodataCodesForIOS("geosite", "dat", site, "succinct-only"); err != nil {
		t.Errorf("a category only the succinct matcher accepts was refused: %v", err)
	}
	if err := ValidateGeodataCodesForIOS("geosite", "dat", site, "mph-only"); err != nil {
		t.Errorf("a category only the mph matcher accepts was refused: %v", err)
	}
	err := ValidateGeodataCodesForIOS("geosite", "dat", site, "neither")
	if err == nil {
		t.Fatal("a category no runtime matcher can build was accepted")
	}
	if !strings.Contains(err.Error(), "either matcher") {
		t.Errorf("the error should say both matchers were tried: %v", err)
	}
}

func TestTheAppValidatorAndTheCoreAgreeOnAnMMDB(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "..", "component", "mmdb", "testdata", "country-a.mmdb"))
	if err != nil {
		t.Fatal(err)
	}

	for _, kind := range []string{"geoip", "asn"} {
		ordinary := writeGeodataFixture(t, source)
		appAccepts := ValidateGeodataForIOS(kind, "mmdb", ordinary) == nil
		coreAccepts := mmdb.Verify(ordinary)
		if !appAccepts || !coreAccepts {
			t.Fatalf("%s: an ordinary database must be accepted by both, app=%v core=%v", kind, appAccepts, coreAccepts)
		}

		oversized := filepath.Join(t.TempDir(), "oversized.mmdb")
		file, err := os.Create(oversized)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write(source); err != nil {
			t.Fatal(err)
		}
		if _, err := file.Seek(mmdb.MaxDatabaseBytes+1-int64(len(source)), io.SeekStart); err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write(source); err != nil {
			t.Fatal(err)
		}
		file.Close()

		appError := ValidateGeodataForIOS(kind, "mmdb", oversized)
		if appError == nil {
			t.Fatalf("%s: the App must not publish a database the core refuses to open", kind)
		}
		if !strings.Contains(appError.Error(), "size") && !strings.Contains(appError.Error(), "larger than") {
			t.Fatalf("%s: the refusal must be about the size, got %v", kind, appError)
		}
		if mmdb.Verify(oversized) {
			t.Fatalf("%s: the core is expected to refuse this file -- if it opens it, the App's refusal is the wrong half", kind)
		}
	}
}

func TestAnOversizedMMDBIsRefusedBeforeItIsRead(t *testing.T) {
	directory := t.TempDir()
	oversized := filepath.Join(directory, "Country.mmdb")
	file, err := os.Create(oversized)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(mmdb.MaxDatabaseBytes + 1); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	for _, kind := range []string{"geoip", "asn"} {
		err := ValidateGeodataForIOS(kind, "mmdb", oversized)
		if err == nil {
			t.Fatalf("%s: an oversized MMDB must be refused", kind)
		}
		if !strings.Contains(err.Error(), "size") {
			t.Fatalf("%s: the refusal must name the ceiling, got %v", kind, err)
		}
	}

	dat := filepath.Join(directory, "GeoSite.dat")
	if err := os.Rename(oversized, dat); err != nil {
		t.Fatal(err)
	}
	if err := ValidateGeodataForIOS("geosite", "dat", dat); err == nil {
		t.Fatal("a file of zeros is not a GeoSite.dat")
	} else if strings.Contains(err.Error(), "size") {
		t.Fatalf("a .dat at that size must not be refused for its size, got %v", err)
	}
}
