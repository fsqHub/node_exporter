// copyright to add

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
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/alecthomas/kingpin/v2"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	// mpamInclude = kingpin.Flag("collector.mpam-include", "Regexp of mpam info to include (mutually exclusive to mpam-exclude).").Default("true").Bool()
	// mpamExclude = kingpin.Flag("collector.mpam-exclude", "Regexp of mpam info to exclude (mutually exclusive to mpam-include).").Default("false").Bool()
	// mpamCacheInclude = kingpin.Flag("collector.mpam.cache-include", "Regexp of mpam cache (config and usage) to include (mutually exclusive to cache-exclude).").String()
	mpamCacheExclude = kingpin.Flag("collector.mpam.cache-exclude", "Regexp of mpam cache (config and usage) to exclude (mutually exclusive to cache-include).").Default("false").Bool()
	// mpamMemInclude   = kingpin.Flag("collector.mpam.mem-include", "Regexp of mpam memory bw (config and usage) to include (mutually exclusive to mem-exclude).").String()
	mpamMemExclude  = kingpin.Flag("collector.mpam.mem-exclude", "Regexp of mpam memory bw (config and usage) to exclude (mutually exclusive to mem-include).").Default("false").Bool()
	resctlMountPath = kingpin.Flag("collector.mpam.resctl.path", "resctl mountpoint.").Default("/sys/fs/resctl").String()

	// DirNameInAGroup is the directory name in a group.
	// It is used to distinguish a mpam (control or monitor) group.
	DirNameInAGroup = "mon_groups"

	// filePathForIDLabel      = "rmid"
	filePathForCpuListLabel = "cpus_list"
	filePathForModeLabel    = "mode"
)

type mpamCollector struct {
	// fs sysfs.FS // 不需要，后续删除
	// deviceFilter deviceFilter
	cacheUsage  *prometheus.Desc
	cacheConfig *prometheus.Desc
	memUsage    *prometheus.Desc
	memConfig   *prometheus.Desc
	logger      *slog.Logger
}
type mpamMetricsCommonLabels struct {
	groupName string
	// id        string
	cpuList string
	mode    string
}

func init() {
	registerCollector("mpam", defaultEnabled, NewMPAMCollector)
}

func NewMPAMCollector(logger *slog.Logger) (Collector, error) {
	// fs, err := sysfs.NewFS(*resctlMountPath)
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to open sysfs: %w", err)
	// }

	return &mpamCollector{
		// fs: fs,
		// deviceFilter: newDeviceFilter(*mpamInclude, *mpamExclude),
		cacheUsage: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "mpam", "l3_cache_usage"),
			"MPAM L3 cache usage.",
			[]string{"group", "id", "cpu_list", "mode"},
			nil,
		),
		cacheConfig: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "mpam", "l3_cache_config"),
			"MPAM L3 cache config.",
			[]string{"group", "id", "cpu_list", "mode"},
			nil,
		),
		memUsage: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "mpam", "mem_usage"),
			"MPAM memory bw usage.",
			[]string{"group", "id", "cpu_list", "mode"},
			nil,
		),
		memConfig: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "mpam", "mem_config"),
			"MPAM memory bw config.",
			[]string{"group", "id", "cpu_list", "mode"},
			nil,
		),
		logger: logger,
	}, nil
}

func (c *mpamCollector) updateCacheMetrics(ch chan<- prometheus.Metric, mpamGroupName string, mpamGroupPath string, labels mpamMetricsCommonLabels) error {
	err := c.updateMPAML3CacheUsage(ch, mpamGroupName, mpamGroupPath, labels)
	if err != nil {
		return fmt.Errorf("failed to get mpam l3 cache usage: %w", err)
	}
	err = c.updateMPAML3CacheConfig(ch, mpamGroupName, mpamGroupPath, labels)
	if err != nil {
		return fmt.Errorf("failed to get mpam l3 cache config: %w", err)
	}
	return nil
}

func (c *mpamCollector) updateMemMetrics(ch chan<- prometheus.Metric, mpamGroupName string, mpamGroupPath string, labels mpamMetricsCommonLabels) error {
	return nil
}

// scan the rootDirPath recursively to find all the dirs which name is TargetSubDir,
// and return a map of target_dir_name to target_dir_path.
// The target_dir_name is the name of the parent dir of the TargetSubDir dir.
func getAllTargetDirs(rootDirPath string, TargetSubDir string) (map[string]string, error) {
	targetDirs := make(map[string]string)

	err := filepath.WalkDir(rootDirPath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		// when we find a TargetSubDir dir,
		// we get the name and path of the parent dir
		if d.IsDir() && d.Name() == TargetSubDir {
			parentDirPath := filepath.Dir(path)
			baseName := filepath.Base(parentDirPath)
			targetDirPath, err := filepath.Rel(rootDirPath, parentDirPath)
			if err != nil {
				return fmt.Errorf("failed to get relative path: %w", err)
			}
			targetDirs[baseName] = targetDirPath
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to walk dir: %w", err)
	}
	return targetDirs, nil
}

func (c *mpamCollector) getMPAMGroups() (map[string]string, error) {
	mpamGroups, err := getAllTargetDirs(*resctlMountPath, DirNameInAGroup)
	if err != nil {
		return nil, fmt.Errorf("failed to get mpam groups: %w", err)
	}
	if len(mpamGroups) == 0 {
		return nil, fmt.Errorf("mpam groups is empty")
	}
	return mpamGroups, err
}

func getFileContent(filePath string) (string, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to read file: %w", err)
	}
	return strings.TrimSpace(string(content)), nil
}
func (c *mpamCollector) getLabels(mpamGroupName string, mpamGroupPath string) (labels mpamMetricsCommonLabels, err error) {
	labels.groupName = mpamGroupName

	cpus, err := getFileContent(filepath.Join(mpamGroupPath, filePathForCpuListLabel))
	if err != nil {
		return labels, fmt.Errorf("failed to get cpus_list: %w", err)
	}
	if cpus == "" {
		cpus = "null"
		c.logger.Info("cpus_list is empty, set to null", "group", mpamGroupName)
	}
	labels.cpuList = cpus
	labels.mode, err = getFileContent(filepath.Join(mpamGroupPath, filePathForModeLabel))
	if err != nil {
		return labels, fmt.Errorf("failed to get mode: %w", err)
	}

	return labels, nil
}
func (c *mpamCollector) Update(ch chan<- prometheus.Metric) error {
	mpamGroups, err := c.getMPAMGroups()
	if err != nil {
		return fmt.Errorf("failed to get mpam groups: %w", err)
	}
	for mpamGroupName, mpamGroupPath := range mpamGroups {
		labels, err := c.getLabels(mpamGroupName, mpamGroupPath)
		if err != nil {
			return fmt.Errorf("failed to get labels: %w", err)
		}
		if !*mpamCacheExclude {
			err := c.updateCacheMetrics(ch, mpamGroupName, mpamGroupPath, labels)
			if err != nil {
				return fmt.Errorf("failed to update cache metrics: %w", err)
			}
		}
		if !*mpamMemExclude {
			err := c.updateMemMetrics(ch, mpamGroupName, mpamGroupPath, labels)
			if err != nil {
				return fmt.Errorf("failed to update mem metrics: %w", err)
			}
		}
	}

	return nil
}
