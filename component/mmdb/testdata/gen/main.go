package main

import (
	"log"
	"net"
	"os"
	"path/filepath"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

const pinnedBuildEpoch = 1_700_000_000

func main() {
	out := ".."
	if len(os.Args) > 1 {
		out = os.Args[1]
	}
	_, prefix, err := net.ParseCIDR("1.0.0.0/24")
	if err != nil {
		log.Fatal(err)
	}
	writeCountry := func(name, code string) {
		tree, err := mmdbwriter.New(mmdbwriter.Options{
			DatabaseType: "GeoLite2-Country", RecordSize: 24, IPVersion: 4,
			Description: map[string]string{"en": "Clash test fixture " + name}, Languages: []string{"en"},
			BuildEpoch: pinnedBuildEpoch,
		})
		if err != nil {
			log.Fatal(err)
		}
		if err := tree.Insert(prefix, mmdbtype.Map{"country": mmdbtype.Map{"iso_code": mmdbtype.String(code)}}); err != nil {
			log.Fatal(err)
		}
		write(filepath.Join(out, name), tree)
	}
	writeASN := func(name string, asn uint32, org string) {
		tree, err := mmdbwriter.New(mmdbwriter.Options{
			DatabaseType: "GeoLite2-ASN", RecordSize: 24, IPVersion: 4,
			Description: map[string]string{"en": "Clash test fixture " + name}, Languages: []string{"en"},
			BuildEpoch: pinnedBuildEpoch,
		})
		if err != nil {
			log.Fatal(err)
		}
		if err := tree.Insert(prefix, mmdbtype.Map{
			"autonomous_system_number":       mmdbtype.Uint32(asn),
			"autonomous_system_organization": mmdbtype.String(org),
		}); err != nil {
			log.Fatal(err)
		}
		write(filepath.Join(out, name), tree)
	}
	metaV0 := func(name string) {
		tree, err := mmdbwriter.New(mmdbwriter.Options{
			DatabaseType: "Meta-geoip0", RecordSize: 24, IPVersion: 4,
			BuildEpoch: pinnedBuildEpoch,
		})
		if err != nil {
			log.Fatal(err)
		}
		if err := tree.Insert(prefix, mmdbtype.Slice{mmdbtype.String("cc"), mmdbtype.String("dd")}); err != nil {
			log.Fatal(err)
		}
		write(filepath.Join(out, name), tree)
	}
	metaV0("metav0-no-description.mmdb")
	malformed := func(name, databaseType string, record mmdbtype.DataType) {
		tree, err := mmdbwriter.New(mmdbwriter.Options{
			DatabaseType: databaseType, RecordSize: 24, IPVersion: 4,
			BuildEpoch: pinnedBuildEpoch,
		})
		if err != nil {
			log.Fatal(err)
		}
		if err := tree.Insert(prefix, record); err != nil {
			log.Fatal(err)
		}
		write(filepath.Join(out, name), tree)
	}
	malformed("metav0-mixed-record.mmdb", "Meta-geoip0",
		mmdbtype.Slice{mmdbtype.String("us"), mmdbtype.Uint32(7)})
	malformed("ipinfo-short-asn.mmdb", "ipinfo generic_asn_free.mmdb",
		mmdbtype.Map{"asn": mmdbtype.String("A"), "name": mmdbtype.String("Fixture")})
	writeCountry("country-a.mmdb", "AA")
	writeCountry("country-b.mmdb", "BB")
	writeASN("asn-a.mmdb", 64500, "Fixture A")
	writeASN("asn-b.mmdb", 64501, "Fixture B")
}

func write(path string, tree *mmdbwriter.Tree) {
	f, err := os.Create(path)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := tree.WriteTo(f); err != nil {
		log.Fatal(err)
	}
	if err := f.Close(); err != nil {
		log.Fatal(err)
	}
}
