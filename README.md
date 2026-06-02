# atop-analyze

`atop-analyze` 是一个基于 Go 的命令行工具，用于解析 Linux `atop` 原始日志文件（rawlog），并生成可视化的 Excel 报表。

> 该工具针对 `atop 2.10` 版本生成的 rawlog 进行开发，其他 atop 版本的 rawlog 尚未经过测试，是否能正常解析未确认。

## 功能

- 解析 `atop` 原始日志文件
- 提取每个采样点的进程 CPU 与内存数据
- 输出终端汇总：CPU 占用 Top N、内存占用 Top N
- 导出 Excel 文件：完整进程数据、CPU 趋势、内存趋势
- 支持通过 `--top` 参数调整导出时的进程数量

## 安装

```bash
git clone https://github.com/yourname/atop-analyze.git
cd atop-analyze
go mod download
```

## 编译

```bash
go build -o atop-analyze main.go
```

## 使用

```bash
./atop-analyze [--top N] <atop_logfile>
```

示例：

```bash
./atop-analyze --top 20 /path/to/atop.raw
```

- `--top N`：可选参数，指定导出 Excel 时保留的进程数量，默认值为 `20`
- `<atop_logfile>`：`atop` rawlog 文件路径

## 输出

工具会在终端打印每个采样点的 CPU Top 3 和内存 Top 3，同时自动生成与输入文件同名的 `.xlsx` 文件。

Excel 输出包含：

- 完整进程数据
- CPU 使用趋势
- 内存使用趋势

## 依赖

- Go 1.22+
- `github.com/xuri/excelize/v2`

## 注意事项

- 目前仅支持 `x86_64 Linux` 上 `atop` rawlog 的解析格式
- 如果日志文件格式与预期不一致，程序会提示警告或失败

## 许可证

请根据需要添加合适的开源许可证，例如 `MIT`、`Apache-2.0` 等。