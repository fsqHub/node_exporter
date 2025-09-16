package collector

import (
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestGetMPAMGroups(t *testing.T) {
	// 创建临时测试目录
	testDir := t.TempDir()
	// 在测试开始前添加
	originalPath := *resctlMountPath
	*resctlMountPath = testDir // 指向临时目录
	defer func() { *resctlMountPath = originalPath }()

	// 模拟正常情况
	t.Run("three_mpam_groups", func(t *testing.T) {

		// 为了避免测试之间的干扰，每个测试都创建一个新的临时目录
		// 创建临时测试目录
		testDir := t.TempDir()
		// 在测试开始前添加
		originalPath := *resctlMountPath
		*resctlMountPath = testDir // 指向临时目录
		defer func() { *resctlMountPath = originalPath }()

		// 创建测试用目录结构
		groupDirs := []string{"groupA", "groupB", "groupC"}
		for _, dir := range groupDirs {
			path := filepath.Join(testDir, dir, DirNameInAGroup)
			os.MkdirAll(path, 0755)
		}

		// 执行测试
		c := &mpamCollector{}
		result, err := c.getMPAMGroups()

		// 验证结果
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if len(result) != len(groupDirs) {
			t.Errorf("Expected %d groups, got %d", len(groupDirs), len(result))
		}
	})

	t.Run("one_group", func(t *testing.T) {
		// 为了避免测试之间的干扰，每个测试都创建一个新的临时目录
		// 创建临时测试目录
		testDir := t.TempDir()
		// 在测试开始前添加
		originalPath := *resctlMountPath
		*resctlMountPath = testDir // 指向临时目录
		defer func() { *resctlMountPath = originalPath }()

		groupDirs := []string{"groupA", "groupB", "groupC"}
		for _, dir := range groupDirs {
			path := filepath.Join(testDir, DirNameInAGroup, dir)
			os.MkdirAll(path, 0755)
		}

		// 执行测试
		c := &mpamCollector{}
		result, err := c.getMPAMGroups()

		// 验证结果
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if len(result) != 1 {
			t.Errorf("wrong result, expect only one result")
		}
	})

	// 模拟错误情况
	t.Run("empty_directory", func(t *testing.T) {
		// 为了避免测试之间的干扰，每个测试都创建一个新的临时目录
		// 创建临时测试目录
		testDir := t.TempDir()
		// 在测试开始前添加
		originalPath := *resctlMountPath
		*resctlMountPath = testDir // 指向临时目录
		defer func() { *resctlMountPath = originalPath }()

		c := &mpamCollector{}
		_, err := c.getMPAMGroups()
		if err == nil {
			t.Error("Expected error but got nil")
		}
	})
}

// ... existing test code ...
func TestGetLabels(t *testing.T) {
	// 保存原始全局变量
	originalPath := *resctlMountPath
	defer func() { *resctlMountPath = originalPath }()

	tests := []struct {
		name        string
		groupPath   string
		mockFiles   map[string]string
		wantLabels  mpamMetricsCommonLabels
		wantError   bool
		logContains string
	}{
		{
			name:      "normal case",
			groupPath: "group1",
			mockFiles: map[string]string{
				"group1/cpus_list": "0-3",
				"group1/mode":      "exclusive",
			},
			wantLabels: mpamMetricsCommonLabels{
				groupName: "group1",
				cpuList:   "0-3",
				mode:      "exclusive",
			},
		},
		{
			name:      "empty cpus_list",
			groupPath: "group2",
			mockFiles: map[string]string{
				"group2/cpus_list": "",
				"group2/mode":      "shared",
			},
			wantLabels: mpamMetricsCommonLabels{
				groupName: "group2",
				cpuList:   "null",
				mode:      "shared",
			},
			logContains: "cpus_list is empty",
		},
		{
			name:      "file not found",
			groupPath: "",
			mockFiles: map[string]string{},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 设置临时目录
			tmpDir := t.TempDir()
			*resctlMountPath = tmpDir

			// 创建模拟文件
			for path, content := range tt.mockFiles {
				fullPath := filepath.Join(tmpDir, "mpam/ctl/groups", path)
				if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
					t.Fatal(err)
				}
			}

			// 初始化collector
			c := &mpamCollector{
				logger: slog.New(slog.NewTextHandler(os.Stdout, nil)),
			}

			// 执行测试
			got, err := c.getLabels(tt.groupPath, filepath.Join(tmpDir, "mpam/ctl/groups", tt.groupPath))

			// 验证错误
			if (err != nil) != tt.wantError {
				t.Fatalf("getLabels() error = %v, wantErr %v", err, tt.wantError)
			}

			// 验证返回值
			if !reflect.DeepEqual(got, tt.wantLabels) {
				t.Errorf("getLabels() = %v, want %v", got, tt.wantLabels)
			}
		})
	}
}

// ... existing test code ...
