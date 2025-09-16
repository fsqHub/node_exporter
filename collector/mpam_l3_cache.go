// copyright

// Copyright 2017 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build !noarp
// +build !noarp

package collector

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	// path where the L3 cache usage info is stored in a mpam group
	dirPathForMPAMGroupData = "mon_data"
	// key in name of the files/dirs that store the L3 cache usage info in dir: dirPathForMPAMGroupData
	nameKeyForCache = "mon_L3"
	// name of the file that store the L3 cache usage info in dir: dirPathForMPAMGroupData/nameKeyForCache+XXX
	fileNameForCache = "llc_occupancy"
)

func listTargetSubdirs(path string, targetPrefix string) ([]string, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory %s: %w", path, err)
	}

	var dirs []string
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), targetPrefix) {
			dirs = append(dirs, entry.Name())
		}
	}
	return dirs, nil
}

func (c *mpamCollector) updateMPAML3CacheUsage(ch chan<- prometheus.Metric, mpamGroup string, mpamGroupPath string, labels mpamMetricsCommonLabels) error {
	L3CacheUsageDirs, err := listTargetSubdirs(filepath.Join(mpamGroupPath, dirPathForMPAMGroupData), nameKeyForCache)
	if err != nil {
		return fmt.Errorf("failed to list L3 cache usage dirs in group %s: %w", mpamGroup, err)
	}

	for _, dir := range L3CacheUsageDirs {
		path := filepath.Join(mpamGroupPath, dirPathForMPAMGroupData, dir, fileNameForCache)
		if _, err := os.Stat(path); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("failed to stat file %s: %w", path, err)
		}
		L3CacheUsage, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read file %s: %w", path, err)
		}
		strValue := strings.TrimSpace(string(L3CacheUsage))
		L3CacheUsageData, err := strconv.ParseFloat(strValue, 64)
		if err != nil {
			return fmt.Errorf("failed to parse L3 cache usage data %s: %w", strValue, err)
		}
		id := filepath.Base(path)
		ch <- prometheus.MustNewConstMetric(
			c.cacheUsage, prometheus.GaugeValue, float64(L3CacheUsageData), labels.groupName, id, labels.cpuList, labels.mode)
	}
	return nil
}
func (c *mpamCollector) updateMPAML3CacheConfig(ch chan<- prometheus.Metric, mpamGroup string, mpamGroupPath string, labels mpamMetricsCommonLabels) error {
	return nil
}
