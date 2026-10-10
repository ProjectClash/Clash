package geodata

import (
	"testing"

	"github.com/ProjectClash/Clash/component/mmdb"
)

func TestTheDownloadAndOpenCeilingsAgree(t *testing.T) {
	if MaxMMDBBytes != mmdb.MaxDatabaseBytes {
		t.Fatalf("MMDB download ceiling %d, open ceiling %d: a database that arrives must be a database that opens",
			MaxMMDBBytes, mmdb.MaxDatabaseBytes)
	}
}

func TestTheDatCeilingIsItsOwnAndLargerThanTheMMDBOne(t *testing.T) {
	if MaxDatFileBytes <= MaxMMDBBytes {
		t.Fatalf(".dat ceiling %d must be larger than the MMDB ceiling %d", MaxDatFileBytes, MaxMMDBBytes)
	}
}
