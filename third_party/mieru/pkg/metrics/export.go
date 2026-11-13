// Copyright (C) 2022  mieru authors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package metrics

import (
	"fmt"
	"os"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/enfein/mieru/v3/pkg/log"
	"github.com/enfein/mieru/v3/pkg/mathext"
	pb "github.com/enfein/mieru/v3/pkg/metrics/metricspb"
	"google.golang.org/protobuf/proto"
)

var logTicker *time.Ticker
var logDuration time.Duration
var metricsDump bool
var metricsDumpFilePath string
var stopLogging chan struct{}
var logMutex sync.Mutex
var dumpMutex sync.Mutex

func init() {
	logDuration = 10 * time.Minute
	stopLogging = make(chan struct{}, 1)
}

func EnableLogging() {
	logMutex.Lock()
	defer logMutex.Unlock()
	if logTicker == nil {
		logTicker = time.NewTicker(logDuration)
	} else {
		logTicker.Reset(logDuration)
	}
	go logMetricsLoop()
	log.Infof("enabled metrics logging with duration %v", logDuration)
}

func DisableLogging() {
	logMutex.Lock()
	defer logMutex.Unlock()
	if len(stopLogging) == 0 {
		stopLogging <- struct{}{}
	}
	if logTicker != nil {
		logTicker.Stop()
		log.Infof("disabled metrics logging")
	}
}

func EnableMetricsDump() error {
	logMutex.Lock()
	defer logMutex.Unlock()
	if metricsDumpFilePath == "" {
		return fmt.Errorf("can't enable metrics dump: file path is not set")
	}
	metricsDump = true
	return nil
}

func DisableMetricsDump() {
	logMutex.Lock()
	defer logMutex.Unlock()
	metricsDump = false
}

func SetLoggingDuration(duration time.Duration) error {
	if duration.Seconds() <= 0 {
		return fmt.Errorf("duration must be a positive number")
	}
	logMutex.Lock()
	defer logMutex.Unlock()
	logDuration = duration
	return nil
}

func SetMetricsDumpFilePath(path string) {
	logMutex.Lock()
	defer logMutex.Unlock()
	metricsDumpFilePath = path
}

func LoadMetricsFromDump() error {
	dumpMutex.Lock()
	defer dumpMutex.Unlock()
	logMutex.Lock()
	defer logMutex.Unlock()
	if metricsDumpFilePath == "" {
		return fmt.Errorf("can't load metrics dump: file path is not set")
	}

	b, err := os.ReadFile(metricsDumpFilePath)
	if err != nil {
		return fmt.Errorf("os.ReadFile() failed: %w", err)
	}
	m := &pb.AllMetrics{}
	if err := proto.Unmarshal(b, m); err != nil {
		return fmt.Errorf("proto.Unmarshal() failed: %w", err)
	}

	var loadFromBytes = func() {
		for _, pbGroup := range m.GetGroups() {
			groupName := pbGroup.GetName()
			if groupName == "" {
				continue
			}
			if group := GetMetricGroupByName(groupName); group != nil {
				for _, pbMetric := range pbGroup.GetMetrics() {
					metricName := pbMetric.GetName()
					if metric, ok := group.GetMetric(metricName); ok {
						if counter, ok := metric.(*Counter); ok {
							loadCounterFromMetricPB(counter, pbMetric)
						}
					}
				}
			} else {
				for _, pbMetric := range pbGroup.GetMetrics() {
					if pbMetric.GetName() == "" {
						continue
					}
					if pbMetric.GetType() == pb.MetricType_COUNTER {
						RegisterMetric(groupName, pbMetric.GetName(), COUNTER)
					} else if pbMetric.GetType() == pb.MetricType_COUNTER_TIME_SERIES {
						RegisterMetric(groupName, pbMetric.GetName(), COUNTER_TIME_SERIES)
					}
				}
			}
		}
	}

	loadFromBytes()
	loadFromBytes()
	return nil
}

func DumpMetricsNow() error {
	if runtime.GOOS == "windows" {
		return nil
	}

	dumpMutex.Lock()
	defer dumpMutex.Unlock()
	logMutex.Lock()
	path := metricsDumpFilePath
	logMutex.Unlock()
	if path == "" {
		return fmt.Errorf("can't dump metrics: file path is not set")
	}

	m := &pb.AllMetrics{}
	pbGroups := make([]*pb.MetricGroup, 0)
	metricMap.Range(func(k, v any) bool {
		group := v.(*MetricGroup)
		pbGroup := &pb.MetricGroup{
			Name: proto.String(group.name),
		}
		pbMetrics := make([]*pb.Metric, 0)
		group.metrics.Range(func(k, v any) bool {
			metric := v.(Metric)
			pbMetrics = append(pbMetrics, ToMetricPB(metric))
			return true
		})
		pbGroup.Metrics = pbMetrics
		pbGroups = append(pbGroups, pbGroup)
		return true
	})
	m.Groups = pbGroups
	b, err := proto.Marshal(m)
	if err != nil {
		return fmt.Errorf("proto.Marshal() failed: %w", err)
	}
	return writeCheckpointFile(path, b, checkpointFileOps{
		createTemp: func(dir, pattern string) (checkpointFile, error) { return os.CreateTemp(dir, pattern) },
		rename:     os.Rename,
		openDir:    func(dir string) (checkpointFile, error) { return os.Open(dir) },
	})
}

func ToMetricPB(src Metric) *pb.Metric {
	dst := &pb.Metric{}
	dst.Name = proto.String(src.Name())
	switch src.Type() {
	case COUNTER:
		dst.Type = pb.MetricType_COUNTER.Enum()
	case COUNTER_TIME_SERIES:
		dst.Type = pb.MetricType_COUNTER_TIME_SERIES.Enum()
	case GAUGE:
		dst.Type = pb.MetricType_GAUGE.Enum()
	default:
		dst.Type = pb.MetricType_UNSPECIFIED.Enum()
	}
	dst.Value = proto.Int64(src.Load())
	if src.Type() == COUNTER_TIME_SERIES {
		value, history := src.(*Counter).historyPB()
		dst.Value = proto.Int64(value)
		dst.History = history
	}
	return dst
}

func FromMetricPB(src *pb.Metric) (Metric, error) {
	if src.GetType() != pb.MetricType_COUNTER && src.GetType() != pb.MetricType_COUNTER_TIME_SERIES && src.GetType() != pb.MetricType_GAUGE {
		return nil, fmt.Errorf("metric type %v is invalid", src.GetType().String())
	}

	var m Metric
	switch src.GetType() {
	case pb.MetricType_COUNTER:
		m = &Counter{
			name: src.GetName(),
		}
		loadCounterFromMetricPB(m.(*Counter), src)
	case pb.MetricType_COUNTER_TIME_SERIES:
		m = &Counter{
			name:       src.GetName(),
			timeSeries: true,
		}
		loadCounterFromMetricPB(m.(*Counter), src)
	case pb.MetricType_GAUGE:
		m = &Gauge{
			name: src.GetName(),
		}
		loadGaugeFromMetricPB(m.(*Gauge), src)
	}
	return m, nil
}

func LogMetricsNow() {
	log.Infof("[metrics]")
	list := MetricGroupList{}
	metricMap.Range(func(k, v any) bool {
		group := v.(*MetricGroup)
		if group.IsLoggingEnabled() {
			list = list.Append(group)
		}
		return true
	})
	sort.Sort(list)
	for _, group := range list {
		log.WithFields(group.NewLogFields()).Infof(group.NewLogMsg())
	}
}

func logMetricsLoop() {
	for {
		select {
		case <-logTicker.C:
			LogMetricsNow()
			logMutex.Lock()
			shouldDump := metricsDump
			logMutex.Unlock()
			if shouldDump {
				if err := DumpMetricsNow(); err != nil {
					log.Warnf("DumpMetricsNow() failed: %v", err)
				}
			}
		case <-stopLogging:
			return
		}
	}
}

func loadCounterFromMetricPB(dst *Counter, src *pb.Metric) {
	if src.GetName() != dst.Name() {
		return
	}

	if (src.GetType() == pb.MetricType_COUNTER && dst.Type() == COUNTER) || (src.GetType() == pb.MetricType_COUNTER_TIME_SERIES && dst.Type() == COUNTER_TIME_SERIES) {
		delta := mathext.Max(0, src.GetValue()-dst.Load())
		dst.Add(delta)
		if dst.timeSeries {
			dst.loadHistory(src.GetHistory())
		}
	}
}

func loadGaugeFromMetricPB(dst *Gauge, src *pb.Metric) {
	if src.GetName() != dst.Name() {
		return
	}

	dst.Store(src.GetValue())
}
