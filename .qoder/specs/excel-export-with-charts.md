# Excel Export with Charts — Implementation Plan

## Context

现有 atop 日志解析工具（`main.go`）已能正确解析 atop 2.10 二进制日志并在控制台输出每个采样点的 CPU/内存 Top 3 进程。用户希望将结果导出为 Excel 表格，并生成 CPU 和内存趋势折线图。

## 方案

在现有代码基础上新增 `exportExcel` 函数，使用 `excelize/v2` 库生成 `.xlsx` 文件，包含 3 个 Sheet。

### Excel 结构

**Sheet 1: "采样数据"** — 明细表（每个采样点的 Top3 进程各一行）

| 列 | 内容 |
|----|------|
| A | 采样序号 |
| B | 时间 |
| C | 间隔(s) |
| D | 类型（启动快照/末次快照/正常） |
| E | 分类（CPU/内存） |
| F | 排名 |
| G | PID |
| H | 进程名 |
| I | CPU% |
| J | CPU Ticks |
| K | 驻留内存(MB) |
| L | 虚拟内存(MB) |
| M | Swap(MB) |
| N | 线程数 |
| O | 状态 |
| P | 命令行 |

**Sheet 2: "CPU趋势"** — 折线图 + 数据透视表
- 数据区从第 20 行开始：A 列=时间, B~N 列=各唯一进程名的 CPU%
- 折线图位于 A1，尺寸约 960×480
- **仅包含正常采样点**（排除累计快照以免扭曲趋势）

**Sheet 3: "内存趋势"** — 折线图 + 数据透视表
- 同上结构，值为驻留内存(MB)

### 图表数据策略：按唯一进程名追踪

每个在 Top3 中出现过的进程名作为一条独立折线。进程不在某个时间点的 Top3 中时，该点留空（图表显示为断点）。最多展示出现频率最高的 10 个进程。

### 代码改动

**文件: `main.go`**
1. 将 `SampleResult` 类型声明移到 `main()` 外部（包级别）
2. 新增 `exportExcel(results []SampleResult, inputFile string, hertz uint16) error` 函数
3. 在 `main()` 的控制台输出之后调用 `exportExcel`

**文件: `go.mod`**
- 添加依赖: `github.com/xuri/excelize/v2`

### 样式
- 表头: 深蓝底白字加粗
- 快照行: 浅黄底色标注
- 数据行: 交替浅蓝底色
- 时间列宽 20, 命令行列宽 50

## 验证

1. `go build` 编译通过
2. 运行 `.\atop-analyze.exe atop_20260417`，确认:
   - 控制台输出不变
   - 生成 `atop_20260417.xlsx`
   - Excel 中 3 个 Sheet 数据正确
   - 两张折线图正常显示
