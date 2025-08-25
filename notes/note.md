# Node Exporter 工作原理分析：

## 核心架构
1. 主入口 node_exporter.go 中：

- 初始化命令行参数（metrics路径、最大并发请求等）
- 创建指标处理器 newHandler
- 启动HTTP服务器

2. 指标收集层：

- 通过 collector 实现各类系统指标采集
- 每个收集器实现 Collector 接口（Collect/Describe 方法）

## 工作流程

```mermaid
sequenceDiagram
    participant Client
    participant Handler
    participant NodeCollector
    participant System

    Client->>Handler: GET /metrics
    Handler->>NodeCollector: 创建过滤后的收集器实例
    NodeCollector->>System: 读取/proc、/sys等数据
    System-->>NodeCollector: 原始指标数据
    NodeCollector->>NodeCollector: 转换为Prometheus格式
    NodeCollector-->>Handler: 指标数据
    Handler-->>Client: HTTP 200响应
```
## 关键函数调用路径
1. main() → newHandler() 初始化核心处理器
2. handler.ServeHTTP() 处理请求：
- 解析 collect[]/exclude[] 参数
- 若无过滤条件，直接使用默认的`unfilteredHandler`处理请求：`unfilteredHandler.ServeHTTP(w, r)`。
- 若有过滤条件，调用·innerHandler·动态创建新的指标处理器`filteredHandler`处理请求: `filteredHandler.ServeHTTP(w, r)`。
1. innerHandler() → collector.NewNodeCollector() 加载具体收集器
2. 各平台专属收集器（如 cpu_linux.go）实现指标采集

## 数据流向
1. 系统调用层：通过读取 /proc、/sys 等伪文件系统
2. 转换层：将原始数据转换为Prometheus指标格式
3. 暴露层：通过HTTP端点输出符合Prometheus规范的metrics数据

## 函数调用图
```mermaid
%% 主流程
sequenceDiagram
    participant main
    participant newHandler
    participant handler
    participant NodeCollector
    participant CPUCollector
    participant FilesystemCollector

    main->>+newHandler: 初始化处理器
    newHandler-->>-main: 返回handler实例
    main->>+web.ListenAndServe: 启动9100端口监听

    loop 请求处理
        web.ListenAndServe->>+handler.ServeHTTP: 接收请求
        handler.ServeHTTP->>+innerHandler: 创建动态处理器
        innerHandler->>+NodeCollector: 加载收集器
        NodeCollector->>+CPUCollector.Update: 采集CPU指标
        NodeCollector->>+FilesystemCollector.Update: 采集文件系统指标
        CPUCollector.Update-->>-NodeCollector: 指标数据
        FilesystemCollector.Update-->>-NodeCollector: 指标数据
        NodeCollector-->>-innerHandler: 聚合数据
        innerHandler-->>-handler.ServeHTTP: 响应内容
        handler.ServeHTTP-->>-web.ListenAndServe: 返回HTTP响应
    end
```
```mermaid
%% 收集器注册关系
graph TD
    main --> collector.NewNodeCollector
    collector.NewNodeCollector --> registerCollector["注册收集器"]
    registerCollector --> CPUCollector
    registerCollector --> FilesystemCollector
    registerCollector --> MemoryCollector
    registerCollector --> NetworkCollector
```
```mermaid
%% 类图简版
classDiagram
    class NodeCollector{
        <<interface>>
        +Describe(ch chan<- *prometheus.Desc)
        +Collect(ch chan<- prometheus.Metric)
    }
    class CPUCollector{
        +Update() error
    }
    class FilesystemCollector{
        +Update() error
    }
    NodeCollector <|.. CPUCollector
    NodeCollector <|.. FilesystemCollector
```

该图包含三个视角：

主流程时序图 - 展示HTTP请求处理全过程
收集器注册关系图 - 显示核心收集器的注册结构
类图简版 - 说明收集器接口实现关系
实际代码包含200+个函数调用关系，此图为简化版本聚焦核心路径。

## newHandler
```mermaid
graph TD
    A[newHandler调用] --> B[创建注册表]
    B --> C{包含exporter自身指标?}
    C -- Yes --> D[注册Process、Go收集器]
    C -- No --> E[创建innerHandler]
    D --> E
    E --> E1[handler.unfilteredHandler = innerHandler]
    E1 --> F[返回handler实例]
```

## innerHandler
```mermaid
graph LR
    A[客户端请求] --> B[并发控制中间件]
    B --> C{包含自身指标?}
    C -- Yes --> D[聚合注册表]
    C -- No --> E[节点指标注册表]
    D --> F[指标序列化]
    E --> F
    F --> G[响应客户端]
```
### 关键机制说明
1. 动态收集器加载：

- filters参数来自URL的collect[]查询参数
- 示例：/metrics?collect[]=cpu&collect[]=memory

2. 双注册表模式：

- h.exporterMetricsRegistry 跟踪导出器自身状态
- r 注册表专注节点指标
- 通过prometheus.Gatherers实现指标聚合

3. 错误韧性设计：
- ContinueOnError确保部分收集器失败不影响整体
- 日志通过slog.NewLogLogger适配传统logger接口

4. 中间件作用：
- InstrumentMetricHandler记录如下监控指标：
  - promhttp_metric_handler_requests_total
  - promhttp_metric_handler_requests_in_flight

## ServeHTTP
haproxy以`promhttp.Handler()`实现httpHandler，当访问/metrics端点时，`promhttp.Handler()`会自动调用已注册采集器的Collect方法。
```go
// 配置HTTP路由，配置API断点
	http.Handle(*metricsPath, promhttp.Handler()) // metrics端点
```
但node exporter以`net/http`实现httpHandler，需要实现`net/http`包的`Handler`接口。
```go
type handler struct {
	unfilteredHandler http.Handler
	// enabledCollectors list is used for logging and filtering
	enabledCollectors []string
	// exporterMetricsRegistry is a separate registry for the metrics about
	// the exporter itself.
	... ...
}

func newHandler(includeExporterMetrics bool, maxRequests int, logger *slog.Logger) *handler {
	// 初始化handler结构体
	h := &handler{
		exporterMetricsRegistry: prometheus.NewRegistry(), // 创建专属注册表
		includeExporterMetrics:  includeExporterMetrics,   // 配置开关
		maxRequests:             maxRequests,              // 并发控制
		logger:                  logger,                   // 日志实例
	}
    ... ... 
}

http.Handle(*metricsPath, newHandler(!*disableExporterMetrics, *maxRequests, logger))
```

ServeHTTP实现了`net/http`包的`Handler`接口:
```go
type Handler interface {
	ServeHTTP(ResponseWriter, *Request)
}
```
`node_exporter.go`中的`handler.ServeHTTP`是Node Exporter处理HTTP请求的核心方法，其作用流程如下：
```mermaid
sequenceDiagram
    participant Client
    participant ServeHTTP
    participant unfilteredHandler
    participant filteredHandler

    Client->>ServeHTTP: 发起/metrics请求
    ServeHTTP->>ServeHTTP: 解析collect[]/exclude[]参数
    alt 无过滤条件
        ServeHTTP->>unfilteredHandler: 直接转发请求
        unfilteredHandler-->>Client: 返回所有指标
    else 包含冲突参数
        ServeHTTP->>Client: 返回400错误
    else 有效过滤条件
        ServeHTTP->>filteredHandler: 创建动态处理器
        filteredHandler-->>Client: 返回过滤后指标
    end
```
### 核心功能：
1. 请求参数解析：

- 处理collect[]（白名单）和exclude[]（黑名单）查询参数
- 示例请求：
  ```http://localhost:9100/metrics?collect[]=cpu&exclude[]=memory```

2. 请求路由决策：

- 无过滤条件时：使用预初始化的unfilteredHandler（全部采集器）
- 参数冲突时：立即返回HTTP 400错误（第99-104行）
- 有效过滤时：动态创建filteredHandler（第114-123行）

3. 动态处理器创建：

- 通过innerHandler方法生成特定过滤条件的处理器链（第116行）
- 包含注册表初始化、采集器加载等复杂逻辑

### 调用时机：
1. HTTP服务器初始化时注册到默认路由：

```go

http.Handle("/metrics", handler)
```

2. 当客户端访问以下地址时自动触发：
- 默认端点：`http://localhost:9100/metrics`
- 自定义配置端点（通过`--web.listen-address`和`--web.telemetry-path`参数）

### 关键设计特点：
1. 并发安全：

- 通过maxRequests限制并发处理数（第23行结构体定义）
- 防止高负载时资源耗尽

2. 日志追踪：

- 使用结构化日志记录请求参数（第88、90行）
- 帮助诊断采集过滤问题

3. 性能优化：

- 无过滤场景使用预编译的处理器（第95-97行）
- 避免每次请求都重新初始化采集器

### 典型调用栈示例：
```go
// 典型调用栈示例
main()
└── http.ListenAndServe()
    └── handler.ServeHTTP()  // 请求到达时
        ├── newHandler()        // 初始化时创建
        └── innerHandler()      // 动态创建过滤处理器
```

## 默认收集器的初始化与加载
### handler的enabledCollectors内容：
```mermaid
classDiagram
    class handler{
        +enabledCollectors []string
        +innerHandler()
    }
    class NodeCollector{
        +Collectors map[string]Collector
    }
    handler --> NodeCollector : 通过innerHandler调用
```

```go
func (h *handler) innerHandler(...) {
    if len(filters) == 0 {
        // 遍历所有启用的收集器
        for n := range nc.Collectors {
            h.enabledCollectors = append(h.enabledCollectors, n)
        }
        sort.Strings(h.enabledCollectors) // 字母排序
        // 日志记录所有启用的收集器
        h.logger.Info("Enabled collectors")
    }
}
```

#### 动态初始化原理：
1. 延迟加载机制：

- 避免在启动时加载所有收集器
- 按需初始化提升启动速度

2. 收集器注册系统：

- 各收集器通过init()注册（如collector/cpu_linux.go）
- 主程序通过NewNodeCollector加载

3. 运行时过滤支持：

- 通过collect[]参数动态过滤
- 保持原始列表完整性用于日志

### NodeCollector.Collectors初始化机制
在collector.go中，Collectors字段的初始化分为两个阶段：

1. 收集器注册阶段（程序启动时）：
```go
// collector.go
// 全局工厂注册表
var factories = make(map[string]func(logger *slog.Logger) (Collector, error))

func registerCollector(collector string, isDefaultEnabled bool, factory func(...)) {
    // 将收集器工厂函数注册到全局map
    factories[collector] = factory
}
```
各子收集器通过init()注册（如cpu_linux.go）：

```go
// cpu_linux.go
func init() {
    registerCollector("cpu", defaultEnabled, NewCPUCollector)
}
```
2. 运行时初始化阶段（首次请求处理）：

```
func NewNodeCollector(logger *slog.Logger, filters ...string) (*NodeCollector, error) {
    collectors := make(map[string]Collector)
    // 遍历所有注册的工厂函数
    for key, factory := range factories {
        collector, err := factory(logger)
        collectors[key] = collector // 实例化收集器
    }
    return &NodeCollector{Collectors: collectors}, nil
}
```
关键时序流程：

```mermaid
sequenceDiagram
    participant node_exporter.go-main()
    participant collector.init()
    participant handler.innerHandler()
    participant NodeCollector.New()

    main.go->>collector.init(): 程序启动
    collector.init()->>+collector.init(): 各子收集器注册
    handler.innerHandler()->>NodeCollector.New(): 首次/metrics请求
    NodeCollector.New()->>factories: 遍历注册表
    factories-->>NodeCollector.New(): 返回所有工厂函数
    NodeCollector.New()->>collectors: 实例化收集器
```
#### 设计特点：
1. 延迟初始化：

- 避免启动时加载所有收集器
- 按需初始化节省资源
2. 线程安全：

- 使用sync.Mutex保护并发访问
- initiatedCollectorsMtx锁机制（第53行）
3. 动态过滤：
- 通过filters参数控制实际启用的收集器

### 各收集器`init()`函数执行机制
在Node Exporter中，各收集器的`init()`函数调用遵循Go语言的包初始化规则：
1. 导入触发阶段：
```go
// node_exporter.go
import (
    _ "github.com/prometheus/node_exporter/collector" // 匿名导入触发初始化
)
```
2. 执行顺序：
- 包级别变量初始化
- `init()`函数按文件字母顺序执行
- 示例收集器初始化顺序：

```mermaid
flowchart LR
    A[arp_linux.go] --> B[conntrack_linux.go]
    B --> C[cpu_linux.go]
    C --> D[diskstats_linux.go]
    D --> E[...]
```
注册过程：

```go
// arp_linux.go
func init() {
    registerCollector("arp", defaultEnabled, NewARPCollector)
}
```
#### 关键代码路径：
1. 主程序入口：node_exporter.go第18-25行（包导入）
2. 各收集器注册调用`registerCollector()`：`collector/collector.go`第59-75行
3. 运行时验证：

```bash
# 查看实际初始化顺序
go build -x 2>&1 | grep 'running init'
```
**设计特点：**
1. 自动注册机制：

- 避免手动维护收集器列表
- **新增收集器只需实现init()**
2. 并发安全：

- 使用initiatedCollectorsMtx互斥锁（collector.go第53行）
- 防止并行初始化冲突
3. 按需编译：

- 通过构建标签控制平台特定收集器
-示例：`diskstats_openbsd_amd64.go`第1行`//go:build amd64 && openbsd`


## `tools/main.go` 函数作用
这是 node_exporter 工具模块的入口函数。主要功能包括：

1. 命令行参数解析：

```go
matchCmd := flag.NewFlagSet("match", flag.ExitOnError)
switch os.Args[1] {
case "match":
    // 处理 match 子命令
```
2. 构建环境匹配检测（match 子命令）：

```go
ctx := build.Context{
    GOOS:   goos,
    GOARCH: goarch,
}
match, err := ctx.MatchFile(filepath.Dir(abs), filepath.Base(abs))
```
该工具用于验证文件是否满足指定 GOOS/GOARCH 的构建条件（通过 // +build 编译标签判断），匹配成功返回 0 退出码，失败返回 1。这是 node_exporter 构建系统用来过滤平台特定源码的辅助工具。