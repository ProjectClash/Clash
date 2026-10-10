package updater

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/ProjectClash/Clash/common/atomic"
	"github.com/ProjectClash/Clash/common/utils"
	"github.com/ProjectClash/Clash/component/geodata"
	_ "github.com/ProjectClash/Clash/component/geodata/standard"
	"github.com/ProjectClash/Clash/component/mmdb"
	"github.com/ProjectClash/Clash/component/resource"
	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/log"

	"golang.org/x/sync/errgroup"
)

var (
	autoUpdate     bool
	updateInterval int

	updatingGeo atomic.Bool
)

func GeoAutoUpdate() bool {
	return autoUpdate
}

func GeoUpdateInterval() int {
	return updateInterval
}

func SetGeoAutoUpdate(newAutoUpdate bool) {
	autoUpdate = newAutoUpdate
}

func SetGeoUpdateInterval(newGeoUpdateInterval int) {
	updateInterval = newGeoUpdateInterval
}

func hashExistingDatabase(path string, ceiling int64) utils.HashType {
	f, err := os.Open(path)
	if err != nil {
		return utils.HashType{}
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.Size() > ceiling {
		return utils.HashType{}
	}
	buf, err := io.ReadAll(io.LimitReader(f, info.Size()))
	if err != nil {
		return utils.HashType{}
	}
	return utils.MakeHash(buf)
}

type geoDatabase struct {
	name    string
	url     func() string
	path    func() string
	ceiling int64
}

var (
	mmdbDatabase    = geoDatabase{"MMDB", geodata.MmdbUrl, func() string { return C.Path.MMDB() }, geodata.MaxMMDBBytes}
	asnDatabase     = geoDatabase{"ASN", geodata.ASNUrl, func() string { return C.Path.ASN() }, geodata.MaxMMDBBytes}
	geoIPDatabase   = geoDatabase{"GeoIP", geodata.GeoIpUrl, func() string { return C.Path.GeoIP() }, geodata.MaxDatFileBytes}
	geoSiteDatabase = geoDatabase{"GeoSite", geodata.GeoSiteUrl, func() string { return C.Path.GeoSite() }, geodata.MaxDatFileBytes}
)

func geoVehicle(url, path string, ceiling int64) *resource.HTTPVehicle {
	return resource.NewHTTPVehicle(url, path, "", nil, defaultHttpTimeout, ceiling+1)
}

func downloadGeoDatabase(db geoDatabase) (data []byte, changed bool, err error) {
	name := db.name
	vehicle := geoVehicle(db.url(), db.path(), db.ceiling)
	oldHash := hashExistingDatabase(vehicle.Path(), db.ceiling)
	data, hash, err := vehicle.Read(context.Background(), oldHash)
	if err != nil {
		return nil, false, fmt.Errorf("can't download %s database file: %w", name, err)
	}
	if int64(len(data)) > db.ceiling {
		return nil, false, fmt.Errorf("can't download %s database file: larger than the %d MiB this accepts", name, db.ceiling>>20)
	}
	if oldHash.Equal(hash) { // same hash, ignored
		return nil, false, nil
	}
	if len(data) == 0 {
		return nil, false, fmt.Errorf("can't download %s database file: no data", name)
	}
	return data, true, nil
}

func UpdateMMDB() (err error) {
	data, changed, err := downloadGeoDatabase(mmdbDatabase)
	if err != nil || !changed {
		return err
	}

	if err := mmdb.PublishIP(data); err != nil {
		return fmt.Errorf("can't save MMDB database file: %w", err)
	}
	return nil
}

func UpdateASN() (err error) {
	data, changed, err := downloadGeoDatabase(asnDatabase)
	if err != nil || !changed {
		return err
	}

	if err := mmdb.PublishASN(data); err != nil {
		return fmt.Errorf("can't save ASN database file: %w", err)
	}
	return nil
}

func UpdateGeoIp() (err error) {
	geoLoader, err := geodata.GetGeoDataLoader("standard")

	path := geoIPDatabase.path()
	data, changed, err := downloadGeoDatabase(geoIPDatabase)
	if err != nil || !changed {
		return err
	}

	if _, err = geoLoader.LoadIPByBytes(data, "cn"); err != nil {
		return fmt.Errorf("invalid GeoIP database file: %s", err)
	}

	defer geodata.ClearGeoIPCache()
	if err = stagedWrite(path, data); err != nil {
		return fmt.Errorf("can't save GeoIP database file: %w", err)
	}
	return nil
}

func UpdateGeoSite() (err error) {
	geoLoader, err := geodata.GetGeoDataLoader("standard")

	path := geoSiteDatabase.path()
	data, changed, err := downloadGeoDatabase(geoSiteDatabase)
	if err != nil || !changed {
		return err
	}

	if _, err = geoLoader.LoadSiteByBytes(data, "cn"); err != nil {
		return fmt.Errorf("invalid GeoSite database file: %s", err)
	}

	defer geodata.ClearGeoSiteCache()
	if err = stagedWrite(path, data); err != nil {
		return fmt.Errorf("can't save GeoSite database file: %w", err)
	}
	return nil
}

func stagedWrite(path string, data []byte) error {
	path, err := mmdb.ResolveLink(path)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".*.staging")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	discard := func() { _ = tmp.Close(); _ = os.Remove(tmpPath) }
	if _, err := tmp.Write(data); err != nil {
		discard()
		return err
	}
	if err := tmp.Sync(); err != nil {
		discard()
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	mode := os.FileMode(0o644)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}
	if err := os.Chmod(tmpPath, mode); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

var updateGeoDatabases = func() error {
	defer runtime.GC()

	b := errgroup.Group{}

	if geodata.GeoIpEnable() {
		if geodata.GeodataMode() {
			b.Go(UpdateGeoIp)
		} else {
			b.Go(UpdateMMDB)
		}
	}

	if geodata.ASNEnable() {
		b.Go(UpdateASN)
	}

	if geodata.GeoSiteEnable() {
		b.Go(UpdateGeoSite)
	}

	return b.Wait()
}

var ErrGetDatabaseUpdateSkip = errors.New("GEO database is updating, skip")

func UpdateGeoDatabases() error {
	log.Infoln("[GEO] Start updating GEO database")

	if !updatingGeo.CompareAndSwap(false, true) {
		return ErrGetDatabaseUpdateSkip
	}
	defer updatingGeo.Store(false)

	log.Infoln("[GEO] Updating GEO database")

	if err := updateGeoDatabases(); err != nil {
		log.Errorln("[GEO] update GEO database error: %s", err.Error())
		return err
	}

	return nil
}

func getUpdateTime() (time time.Time, err error) {
	filesToCheck := []string{
		C.Path.GeoIP(),
		C.Path.MMDB(),
		C.Path.ASN(),
		C.Path.GeoSite(),
	}

	for _, file := range filesToCheck {
		var fileInfo os.FileInfo
		fileInfo, err = os.Stat(file)
		if err == nil {
			return fileInfo.ModTime(), nil
		}
	}

	return
}

func RegisterGeoUpdater() {
	if updateInterval <= 0 {
		log.Errorln("[GEO] Invalid update interval: %d", updateInterval)
		return
	}

	go func() {
		ticker := time.NewTicker(time.Duration(updateInterval) * time.Hour)
		defer ticker.Stop()

		lastUpdate, err := getUpdateTime()
		if err != nil {
			log.Errorln("[GEO] Get GEO database update time error: %s", err.Error())
			return
		}

		log.Infoln("[GEO] last update time %s", lastUpdate)
		if lastUpdate.Add(time.Duration(updateInterval) * time.Hour).Before(time.Now()) {
			log.Infoln("[GEO] Database has not been updated for %v, update now", time.Duration(updateInterval)*time.Hour)
			if err := UpdateGeoDatabases(); err != nil {
				log.Errorln("[GEO] Failed to update GEO database: %s", err.Error())
				return
			}
		}

		for range ticker.C {
			log.Infoln("[GEO] updating database every %d hours", updateInterval)
			if err := UpdateGeoDatabases(); err != nil {
				log.Errorln("[GEO] Failed to update GEO database: %s", err.Error())
			}
		}
	}()
}
