package main

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/xuri/excelize/v2"
)

const (
	MAGIC = uint32(0xfeedbeef)
	TOP_N = 3
)

// TOP_FULL can be set via command line flag --top
var TOP_FULL = 20

// ========== rawheader field offsets (from atop rawlog.h) ==========
// All offsets are for x86_64 Linux, little-endian
const (
	rhMagicOff      = 0  // uint32
	rhAversionOff   = 4  // uint16
	rhRawheadlenOff = 10 // uint16
	rhRawreclenOff  = 12 // uint16
	rhHertzOff      = 14 // uint16
	rhSstatlenOff   = 28 // uint32
	rhTstatlenOff   = 32 // uint32
	rhMinHeaderRead = 36 // minimum bytes to read from header
)

// ========== rawrecord field offsets ==========
const (
	rrCurtimeOff  = 0  // int64 (time_t)
	rrFlagsOff    = 8  // uint16
	rrScomplenOff = 16 // uint32
	rrPcomplenOff = 20 // uint32
	rrIntervalOff = 24 // uint32
	rrNdeviatOff  = 28 // uint32
)

// rawrecord flags
const (
	RRBOOT = 0x0001
	RRLAST = 0x0002
)

// ========== tstat field offsets ==========
// Calculated from struct layout in photoproc.h with x86_64 alignment rules:
//
// gen sub-struct (456 bytes with padding):
//   tgid(4) pid(4) ppid(4) ruid(4) euid(4) suid(4) fsuid(4) rgid(4)
//   egid(4) sgid(4) fsgid(4) nthr(4) name[16] isproc(1) state(1) pad(2)
//   excode(4) btime(8) elaps(8) cmdline[256]
//   nthrslpi(4) nthrslpu(4) nthrrun(4) nthridle(4) ctid(4) vpid(4)
//   wasinactive(4) utsname[16] cgpath[64] pad(4)  => total 456
//
// cpu sub-struct (136 bytes):
//   utime(8) stime(8) nice..cgcpumaxr(9*4=36) ifuture[3](12) wchan[16]
//   rundelay(8) blkdelay(8) nvcsw(8) nivcsw(8) cfuture[3](24)  => total 136
//
// dsk sub-struct (72 bytes):
//   rio(8) rsz(8) wio(8) wsz(8) cwsz(8) cfuture[4](32) => total 72
//
// mem sub-struct (160 bytes):
//   minflt(8) majflt(8) vexec(8) vmem(8) rmem(8) pmem(8) vgrow(8) rgrow(8)
//   vdata(8) vstack(8) vlibs(8) vswap(8) vlock(8) cgmemmax(8) cgmemmaxr(8)
//   cgswpmax(8) cgswpmaxr(8) cfuture[3](24) => total 160
//
// net sub-struct (112 bytes):
//   tcpsnd..avail2(10*8=80) cfuture[4](32) => total 112
//
// gpu sub-struct (56 bytes):
//   state(1) cfuture[3](3) nrgpus(2) pad(2) gpulist(4) gpubusy(4) membusy(4)
//   pad(4) timems(8) memnow(8) memcum(8) sample(8) => total 56
//
// Total expected tstat size: 456 + 136 + 72 + 160 + 112 + 56 = 992

const (
	// gen offsets (relative to tstat start)
	offGenPid     = 4
	offGenNthr    = 44
	offGenName    = 48 // char[16]
	offGenIsproc  = 64 // char (1=process, 0=thread)
	offGenState   = 65 // char
	offGenCmdline = 88 // char[256]

	// cpu offsets (gen size = 456)
	offCpuBase  = 456
	offCpuUtime = offCpuBase + 0 // count_t (int64), ticks
	offCpuStime = offCpuBase + 8 // count_t (int64), ticks

	// dsk offset
	offDskBase = offCpuBase + 136 // = 592

	// mem offsets (dsk size = 72)
	offMemBase  = offDskBase + 72 // = 664
	offMemVmem  = offMemBase + 24 // count_t (int64), KB
	offMemRmem  = offMemBase + 32 // count_t (int64), KB
	offMemVswap = offMemBase + 88 // count_t (int64), KB

	expectedTstatSize = 992
)

// ProcessInfo stores per-process metrics extracted from a tstat entry
type ProcessInfo struct {
	PID      int32
	Name     string
	Cmdline  string
	State    byte
	Nthr     int32
	CPUTicks int64   // utime + stime (ticks in this interval)
	CPUPct   float64 // estimated CPU% during the interval
	RmemKB   int64   // resident memory (KB)
	VmemKB   int64   // virtual memory (KB)
	VswapKB  int64   // swap usage (KB)
}

// SampleResult holds the analysis results for one sampling point
type SampleResult struct {
	Time     time.Time
	Interval uint32
	Flags    uint16
	TopCPU   []ProcessInfo // Top 3 by CPU (for terminal display)
	TopMem   []ProcessInfo // Top 3 by memory (for terminal display)
	Top20CPU []ProcessInfo // Top 20 by CPU (for full process sheet & CPU trend)
	Top20Mem []ProcessInfo // Top 20 by memory (for full process sheet & memory trend)
}

// --- binary read helpers (little-endian) ---

func u16(buf []byte, off int) uint16 {
	return binary.LittleEndian.Uint16(buf[off:])
}

func u32(buf []byte, off int) uint32 {
	return binary.LittleEndian.Uint32(buf[off:])
}

func i32(buf []byte, off int) int32 {
	return int32(binary.LittleEndian.Uint32(buf[off:]))
}

func i64(buf []byte, off int) int64 {
	return int64(binary.LittleEndian.Uint64(buf[off:]))
}

// cstr extracts a null-terminated C string from a byte slice
func cstr(buf []byte, off, maxLen int) string {
	end := off + maxLen
	if end > len(buf) {
		end = len(buf)
	}
	s := buf[off:end]
	if idx := bytes.IndexByte(s, 0); idx >= 0 {
		s = s[:idx]
	}
	return string(s)
}

// zlibDecompress decompresses zlib-compressed data
func zlibDecompress(data []byte, expectedSize int) ([]byte, error) {
	r, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("zlib.NewReader: %w", err)
	}
	defer r.Close()

	buf := make([]byte, expectedSize)
	n, err := io.ReadFull(r, buf)
	if err != nil && err != io.ErrUnexpectedEOF {
		return nil, fmt.Errorf("zlib read (%d/%d bytes): %w", n, expectedSize, err)
	}
	return buf[:n], nil
}

// formatMemory formats KB to a human-readable string
func formatMemory(kb int64) string {
	if kb < 1024 {
		return fmt.Sprintf("%d KB", kb)
	}
	mb := float64(kb) / 1024.0
	if mb < 1024 {
		return fmt.Sprintf("%.1f MB", mb)
	}
	gb := mb / 1024.0
	return fmt.Sprintf("%.2f GB", gb)
}

func main() {
	// Parse command line arguments
	var topCount int
	flag.IntVar(&topCount, "top", 20, "Number of top processes to collect per sample (default: 20)")
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Usage: %s [--top N] <atop_logfile>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  --top N  Number of top processes to collect per sample (default: 20)\n")
		os.Exit(1)
	}
	filename := flag.Arg(0)

	// Set TOP_FULL dynamically
	TOP_FULL = topCount

	f, err := os.Open(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: cannot open file %s: %v\n", filename, err)
		os.Exit(1)
	}
	defer f.Close()

	// ---- Step 1: Read rawheader ----
	headerBuf := make([]byte, rhMinHeaderRead)
	if _, err := io.ReadFull(f, headerBuf); err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to read rawheader: %v\n", err)
		os.Exit(1)
	}

	magic := u32(headerBuf, rhMagicOff)
	if magic != MAGIC {
		fmt.Fprintf(os.Stderr, "Error: invalid magic number 0x%08x (expected 0x%08x)\n", magic, MAGIC)
		os.Exit(1)
	}

	aversion := u16(headerBuf, rhAversionOff)
	rawheadlen := u16(headerBuf, rhRawheadlenOff)
	rawreclen := u16(headerBuf, rhRawreclenOff)
	hertz := u16(headerBuf, rhHertzOff)
	sstatlen := u32(headerBuf, rhSstatlenOff)
	tstatlen := u32(headerBuf, rhTstatlenOff)

	major := (aversion & 0x7F00) >> 8
	minor := aversion & 0x00FF

	fmt.Println("===== ATOP 日志文件分析工具 =====")
	fmt.Printf("文件:          %s\n", filename)
	fmt.Printf("atop 版本:     %d.%d\n", major, minor)
	fmt.Printf("rawheadlen:    %d bytes\n", rawheadlen)
	fmt.Printf("rawreclen:     %d bytes\n", rawreclen)
	fmt.Printf("Hertz (HZ):    %d\n", hertz)
	fmt.Printf("sstat 大小:    %d bytes\n", sstatlen)
	fmt.Printf("tstat 大小:    %d bytes\n", tstatlen)

	if tstatlen != expectedTstatSize {
		fmt.Printf("警告: tstat 大小 %d 与预期 %d 不一致，解析结果可能不正确\n", tstatlen, expectedTstatSize)
	}
	fmt.Println()

	// Seek past the full rawheader
	if _, err := f.Seek(int64(rawheadlen), io.SeekStart); err != nil {
		fmt.Fprintf(os.Stderr, "Error: cannot seek past rawheader: %v\n", err)
		os.Exit(1)
	}

	// ---- Step 2: Iterate over samples ----
	recBuf := make([]byte, rawreclen)
	sampleNum := 0

	// Collect all output for summary
	var results []SampleResult

	for {
		// Read rawrecord
		if _, err := io.ReadFull(f, recBuf); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			}
			fmt.Fprintf(os.Stderr, "Error: reading rawrecord #%d: %v\n", sampleNum+1, err)
			os.Exit(1)
		}

		curtime := i64(recBuf, rrCurtimeOff)
		flags := u16(recBuf, rrFlagsOff)
		scomplen := u32(recBuf, rrScomplenOff)
		pcomplen := u32(recBuf, rrPcomplenOff)
		interval := u32(recBuf, rrIntervalOff)
		ndeviat := u32(recBuf, rrNdeviatOff)
		sampleNum++

		t := time.Unix(curtime, 0)

		// Skip compressed sstat
		if scomplen > 0 {
			if _, err := f.Seek(int64(scomplen), io.SeekCurrent); err != nil {
				fmt.Fprintf(os.Stderr, "Error: cannot skip sstat in sample #%d: %v\n", sampleNum, err)
				os.Exit(1)
			}
		}

		// Read compressed tstat data
		if pcomplen == 0 || ndeviat == 0 {
			results = append(results, SampleResult{Time: t, Interval: interval, Flags: flags})
			continue
		}

		pcompBuf := make([]byte, pcomplen)
		if _, err := io.ReadFull(f, pcompBuf); err != nil {
			fmt.Fprintf(os.Stderr, "Error: reading compressed tstat in sample #%d: %v\n", sampleNum, err)
			os.Exit(1)
		}

		// Decompress tstat array
		uncompSize := int(tstatlen) * int(ndeviat)
		tstatData, err := zlibDecompress(pcompBuf, uncompSize)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: decompression failed in sample #%d: %v (skipping)\n", sampleNum, err)
			results = append(results, SampleResult{Time: t, Interval: interval, Flags: flags})
			continue
		}

		// Parse each tstat entry
		var processes []ProcessInfo
		tsLen := int(tstatlen)
		for i := 0; i < int(ndeviat); i++ {
			off := i * tsLen
			if off+tsLen > len(tstatData) {
				break
			}
			ts := tstatData[off : off+tsLen]

			// Only interested in processes, skip threads
			isproc := ts[offGenIsproc]
			if isproc == 0 {
				continue
			}

			pid := i32(ts, offGenPid)
			name := cstr(ts, offGenName, 16)
			cmdline := cstr(ts, offGenCmdline, 256)
			state := ts[offGenState]
			nthr := i32(ts, offGenNthr)

			utime := i64(ts, offCpuUtime)
			stime := i64(ts, offCpuStime)
			cpuTicks := utime + stime

			vmem := i64(ts, offMemVmem)
			rmem := i64(ts, offMemRmem)
			vswap := i64(ts, offMemVswap)

			// Calculate CPU%: ticks used / total ticks available in the interval
			// For boot samples (cumulative), CPU% is averaged over entire uptime
			var cpuPct float64
			if interval > 0 && hertz > 0 {
				totalTicks := int64(hertz) * int64(interval)
				cpuPct = float64(cpuTicks) * 100.0 / float64(totalTicks)
			}

			processes = append(processes, ProcessInfo{
				PID:      pid,
				Name:     name,
				Cmdline:  cmdline,
				State:    state,
				Nthr:     nthr,
				CPUTicks: cpuTicks,
				CPUPct:   cpuPct,
				RmemKB:   rmem,
				VmemKB:   vmem,
				VswapKB:  vswap,
			})
		}

		// Sort by CPU (descending)
		cpuSorted := make([]ProcessInfo, len(processes))
		copy(cpuSorted, processes)
		sort.Slice(cpuSorted, func(i, j int) bool {
			return cpuSorted[i].CPUTicks > cpuSorted[j].CPUTicks
		})

		// Sort by Resident Memory (descending)
		memSorted := make([]ProcessInfo, len(processes))
		copy(memSorted, processes)
		sort.Slice(memSorted, func(i, j int) bool {
			return memSorted[i].RmemKB > memSorted[j].RmemKB
		})

		topCPU := cpuSorted
		if len(topCPU) > TOP_N {
			topCPU = topCPU[:TOP_N]
		}
		topMem := memSorted
		if len(topMem) > TOP_N {
			topMem = topMem[:TOP_N]
		}
	// Prepare Top20 slices by copying and limiting to TOP_FULL (20)
	top20CPU := make([]ProcessInfo, len(cpuSorted))
	copy(top20CPU, cpuSorted)
	if len(top20CPU) > TOP_FULL {
		top20CPU = top20CPU[:TOP_FULL]
	}
	top20Mem := make([]ProcessInfo, len(memSorted))
	copy(top20Mem, memSorted)
	if len(top20Mem) > TOP_FULL {
		top20Mem = top20Mem[:TOP_FULL]
	}

		results = append(results, SampleResult{
			Time:     t,
			Interval: interval,
			Flags:    flags,
			TopCPU:   topCPU,
			TopMem:   topMem,
				Top20CPU: top20CPU,
		Top20Mem: top20Mem,
		})
	}

	// ---- Step 3: Output results ----
	separator := strings.Repeat("=", 110)
	thinSep := strings.Repeat("-", 106)

	for i, r := range results {
		fmt.Println(separator)

		// Build sample label with flags
		isCumulative := r.Flags&(RRBOOT|RRLAST) != 0 || r.Interval > 86400
		label := ""
		if isCumulative {
			if i == len(results)-1 {
				label = " [末次快照]"
			} else {
				label = " [启动快照]"
			}
		}

		intervalStr := fmt.Sprintf("%ds", r.Interval)
		if isCumulative {
			d := r.Interval
			days := d / 86400
			hours := (d % 86400) / 3600
			mins := (d % 3600) / 60
			intervalStr = fmt.Sprintf("%dd %dh %dm (自启动累计)", days, hours, mins)
		}

		fmt.Printf(" 采样 #%-4d | 时间: %s | 间隔: %s%s\n",
			i+1, r.Time.Format("2006-01-02 15:04:05"), intervalStr, label)
		fmt.Println(separator)

		if len(r.TopCPU) == 0 && len(r.TopMem) == 0 {
			fmt.Println("  (无进程数据)")
			fmt.Println()
			continue
		}

		// CPU Top N
		fmt.Printf("\n  >>> CPU 占用 Top %d (按 CPU 使用降序) <<<\n\n", TOP_N)
		fmt.Printf("    %-8s %-16s %-6s %-6s %-10s %-12s  %s\n",
			"PID", "进程名", "状态", "线程", "CPU%", "CPU Ticks", "命令行")
		fmt.Printf("    %s\n", thinSep)
		for _, p := range r.TopCPU {
			cmd := p.Cmdline
			if len(cmd) > 55 {
				cmd = cmd[:55] + "..."
			}
			if cmd == "" {
				cmd = "-"
			}
			fmt.Printf("    %-8d %-16s %-6c %-6d %-10.2f %-12d  %s\n",
				p.PID, p.Name, p.State, p.Nthr, p.CPUPct, p.CPUTicks, cmd)
		}

		// Memory Top N
		fmt.Printf("\n  >>> 内存占用 Top %d (按驻留内存降序) <<<\n\n", TOP_N)
		fmt.Printf("    %-8s %-16s %-6s %-12s %-12s %-10s  %s\n",
			"PID", "进程名", "状态", "驻留内存", "虚拟内存", "Swap", "命令行")
		fmt.Printf("    %s\n", thinSep)
		for _, p := range r.TopMem {
			cmd := p.Cmdline
			if len(cmd) > 45 {
				cmd = cmd[:45] + "..."
			}
			if cmd == "" {
				cmd = "-"
			}
			fmt.Printf("    %-8d %-16s %-6c %-12s %-12s %-10s  %s\n",
				p.PID, p.Name, p.State,
				formatMemory(p.RmemKB), formatMemory(p.VmemKB),
				formatMemory(p.VswapKB), cmd)
		}
		fmt.Println()
	}

	fmt.Println(separator)
	fmt.Printf(" 分析完成: 共处理 %d 个采样点\n", sampleNum)
	fmt.Println(separator)

	// ---- Step 4: Export to Excel ----
	ext := filepath.Ext(filename)
	xlsxPath := strings.TrimSuffix(filename, ext) + ".xlsx"
	if err := exportExcel(results, xlsxPath); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Excel 导出失败: %v\n", err)
	} else {
		fmt.Printf("\nExcel 已导出: %s\n", xlsxPath)
	}
}

// ========================================================================
// Excel Export
// ========================================================================

// isCumulative returns true for boot/last cumulative snapshot samples
func isCumulative(r SampleResult, idx, total int) bool {
	return r.Flags&(RRBOOT|RRLAST) != 0 || r.Interval > 86400
}

// sampleTypeLabel returns the Chinese label for the sample type
func sampleTypeLabel(r SampleResult, idx, total int) string {
	if isCumulative(r, idx, total) {
		if idx == total-1 {
			return "末次快照"
		}
		return "启动快照"
	}
	return "正常"
}

// pivotData holds the pivoted time-series data for one trend chart
type pivotData struct {
	procNames []string             // unique process names (column headers)
	times     []time.Time          // timestamps (row labels)
	values    []map[string]float64 // per-row: procName -> value
}

// buildPivot scans results and builds pivoted time-series data.
// mode is "cpu" or "mem". Cumulative snapshots are excluded from trend data.
// For processes not present at a given time, value is 0 (not missing).
// CPU趋势使用Top20CPU数据，内存趋势使用Top20Mem数据。
func buildPivot(results []SampleResult, mode string) pivotData {
	// Choose source based on mode
	var sourceProcs [][]ProcessInfo
	for _, r := range results {
		if mode == "cpu" {
			sourceProcs = append(sourceProcs, r.Top20CPU)
		} else {
			sourceProcs = append(sourceProcs, r.Top20Mem)
		}
	}

	// Count frequency of each process name across all processes
	freq := map[string]int{}
	for i, r := range results {
		if isCumulative(r, i, len(results)) {
			continue
		}
		// Use the appropriate Top20 list for counting
		seen := map[string]bool{}
		src := sourceProcs[i]
		for _, p := range src {
			if !seen[p.Name] {
				freq[p.Name]++
				seen[p.Name] = true
			}
		}
	}

	// Sort process names by frequency descending, cap at 10
	type nameFreq struct {
		name string
		cnt  int
	}
	var nf []nameFreq
	for n, c := range freq {
		nf = append(nf, nameFreq{n, c})
	}
	sort.Slice(nf, func(i, j int) bool {
		if nf[i].cnt != nf[j].cnt {
			return nf[i].cnt > nf[j].cnt
		}
		return nf[i].name < nf[j].name
	})
	maxProcs := 10
	if len(nf) < maxProcs {
		maxProcs = len(nf)
	}
	procNames := make([]string, maxProcs)
	procSet := map[string]bool{}
	for i := 0; i < maxProcs; i++ {
		procNames[i] = nf[i].name
		procSet[nf[i].name] = true
	}

	// Build pivot rows (only normal samples)
	// Initialize row with 0 values for all tracked processes
	var times []time.Time
	var values []map[string]float64
	for i, r := range results {
		if isCumulative(r, i, len(results)) {
			continue
		}

		// Initialize all tracked process values to 0
		row := map[string]float64{}
		for _, name := range procNames {
			row[name] = 0.0
		}

		// Fill in actual values from appropriate Top20 list
		src := sourceProcs[i]
		for _, p := range src {
			if !procSet[p.Name] {
				continue
			}
			var val float64
			if mode == "cpu" {
				val = p.CPUPct
			} else {
				val = float64(p.RmemKB) / 1024.0 // MB
			}
			row[p.Name] = val
		}
		times = append(times, r.Time)
		values = append(values, row)
	}

	return pivotData{procNames: procNames, times: times, values: values}
}

func exportExcel(results []SampleResult, outputPath string) error {
	f := excelize.NewFile()
	defer f.Close()

	// Rename the default Sheet1 to "完整进程数据"
	f.SetSheetName("Sheet1", "完整进程数据")

	// ---- Define styles ----
	headerStyle, _ := f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Bold: true, Color: "#FFFFFF", Size: 11},
		Fill:      excelize.Fill{Type: "pattern", Color: []string{"#4472C4"}, Pattern: 1},
		Alignment: &excelize.Alignment{Horizontal: "center", Vertical: "center"},
		Border: []excelize.Border{
			{Type: "bottom", Color: "#2F5496", Style: 1},
		},
	})

	// ---- Sheet 1: 完整进程数据 (合并CPU和内存Top数据) ----
	if err := writeFullProcessSheet(f, results, headerStyle); err != nil {
		return fmt.Errorf("writing full process sheet: %w", err)
	}

	// ---- Sheet 2: CPU趋势 ----
	if err := writeTrendSheet(f, results, "CPU趋势",
		"CPU % 趋势 — Top 进程", "CPU %", "cpu", headerStyle); err != nil {
		return fmt.Errorf("writing CPU trend sheet: %w", err)
	}

	// ---- Sheet 3: 内存趋势 ----
	if err := writeTrendSheet(f, results, "内存趋势",
		"内存趋势 — Top 进程 (驻留内存 MB)", "驻留内存 (MB)", "mem", headerStyle); err != nil {
		return fmt.Errorf("writing memory trend sheet: %w", err)
	}

	// Set active sheet to 完整进程数据
	idx, _ := f.GetSheetIndex("完整进程数据")
	f.SetActiveSheet(idx)

	return f.SaveAs(outputPath)
}

// writeFullProcessSheet writes a sheet containing both CPU and Memory top processes
func writeFullProcessSheet(f *excelize.File, results []SampleResult, headerStyle int) error {
	const fullSheet = "完整进程数据"

	// Create sheet
	// Note: Since we renamed Sheet1 to "完整进程数据", we just use that existing sheet
	// No need to create a new one

	// Write headers
	headers := []string{
		"时间", "分类", "PID", "进程名", "CPU%", "CPU Ticks",
		"驻留内存(MB)", "虚拟内存(MB)", "Swap(MB)",
		"线程数", "状态", "命令行",
	}
	for col, h := range headers {
		cell, _ := excelize.CoordinatesToCellName(col+1, 1)
		f.SetCellValue(fullSheet, cell, h)
	}
	headerEnd, _ := excelize.CoordinatesToCellName(len(headers), 1)
	f.SetCellStyle(fullSheet, "A1", headerEnd, headerStyle)

	// Column widths
	colWidths := map[string]float64{
		"A": 20, "B": 10, "C": 10, "D": 18, "E": 10, "F": 14,
		"G": 14, "H": 14, "I": 12, "J": 8, "K": 6, "L": 55,
	}
	for col, w := range colWidths {
		f.SetColWidth(fullSheet, col, col, w)
	}

	// Write data rows (skip cumulative snapshots)
	row := 2

	for i, r := range results {
		if isCumulative(r, i, len(results)) {
			continue
		}
		timeStr := r.Time.Format("2006-01-02 15:04:05")

		// Write CPU Top data
		for _, p := range r.Top20CPU {
			f.SetCellValue(fullSheet, cellName(1, row), timeStr)
			f.SetCellValue(fullSheet, cellName(2, row), "CPU")
			f.SetCellValue(fullSheet, cellName(3, row), p.PID)
			f.SetCellValue(fullSheet, cellName(4, row), p.Name)
			f.SetCellValue(fullSheet, cellName(5, row), p.CPUPct)
			f.SetCellValue(fullSheet, cellName(6, row), p.CPUTicks)
			f.SetCellValue(fullSheet, cellName(7, row), float64(p.RmemKB)/1024.0)
			f.SetCellValue(fullSheet, cellName(8, row), float64(p.VmemKB)/1024.0)
			f.SetCellValue(fullSheet, cellName(9, row), float64(p.VswapKB)/1024.0)
			f.SetCellValue(fullSheet, cellName(10, row), p.Nthr)
			f.SetCellValue(fullSheet, cellName(11, row), string(rune(p.State)))
			f.SetCellValue(fullSheet, cellName(12, row), p.Cmdline)
			row++
		}

		// Write Memory Top data
		for _, p := range r.Top20Mem {
			f.SetCellValue(fullSheet, cellName(1, row), timeStr)
			f.SetCellValue(fullSheet, cellName(2, row), "内存")
			f.SetCellValue(fullSheet, cellName(3, row), p.PID)
			f.SetCellValue(fullSheet, cellName(4, row), p.Name)
			f.SetCellValue(fullSheet, cellName(5, row), p.CPUPct)
			f.SetCellValue(fullSheet, cellName(6, row), p.CPUTicks)
			f.SetCellValue(fullSheet, cellName(7, row), float64(p.RmemKB)/1024.0)
			f.SetCellValue(fullSheet, cellName(8, row), float64(p.VmemKB)/1024.0)
			f.SetCellValue(fullSheet, cellName(9, row), float64(p.VswapKB)/1024.0)
			f.SetCellValue(fullSheet, cellName(10, row), p.Nthr)
			f.SetCellValue(fullSheet, cellName(11, row), string(rune(p.State)))
			f.SetCellValue(fullSheet, cellName(12, row), p.Cmdline)
			row++
		}
	}

	return nil
}

func writeTrendSheet(f *excelize.File, results []SampleResult,
	sheetName, chartTitle, yAxisTitle, mode string, headerStyle int) error {

	f.NewSheet(sheetName)

	pivot := buildPivot(results, mode)
	if len(pivot.times) == 0 || len(pivot.procNames) == 0 {
		f.SetCellValue(sheetName, "A1", "无可用趋势数据")
		return nil
	}

	// Data table starts at row 20 to leave room for the chart
	const dataStartRow = 20

	// Write header row
	f.SetCellValue(sheetName, cellName(1, dataStartRow), "时间")
	for ci, name := range pivot.procNames {
		f.SetCellValue(sheetName, cellName(ci+2, dataStartRow), name)
	}
	headerEnd, _ := excelize.CoordinatesToCellName(len(pivot.procNames)+1, dataStartRow)
	hdrStart, _ := excelize.CoordinatesToCellName(1, dataStartRow)
	f.SetCellStyle(sheetName, hdrStart, headerEnd, headerStyle)

	// Column widths
	f.SetColWidth(sheetName, "A", "A", 20)
	lastColName, _ := excelize.ColumnNumberToName(len(pivot.procNames) + 1)
	f.SetColWidth(sheetName, "B", lastColName, 14)

	// Write data rows (all values are now initialized to 0 if not present)
	for ri, t := range pivot.times {
		dataRow := dataStartRow + 1 + ri
		f.SetCellValue(sheetName, cellName(1, dataRow), t.Format("2006-01-02 15:04:05"))
		for ci, name := range pivot.procNames {
			val := pivot.values[ri][name] // always exists, may be 0
			f.SetCellValue(sheetName, cellName(ci+2, dataRow), val)
		}
	}

	// Build chart series
	lastDataRow := dataStartRow + len(pivot.times)
	catRange := fmt.Sprintf("'%s'!%s:%s", sheetName,
		cellName(1, dataStartRow+1), cellName(1, lastDataRow))

	var series []excelize.ChartSeries
	for ci := range pivot.procNames {
		col := ci + 2
		nameCell := cellName(col, dataStartRow)
		valRange := fmt.Sprintf("'%s'!%s:%s", sheetName,
			cellName(col, dataStartRow+1), cellName(col, lastDataRow))

		series = append(series, excelize.ChartSeries{
			Name:       fmt.Sprintf("'%s'!%s", sheetName, nameCell),
			Categories: catRange,
			Values:     valRange,
		})
	}

	// Add chart
	if err := f.AddChart(sheetName, "A1", &excelize.Chart{
		Type:   excelize.Line,
		Series: series,
		Title: []excelize.RichTextRun{
			{Text: chartTitle},
		},
		YAxis: excelize.ChartAxis{
			Title: []excelize.RichTextRun{{Text: yAxisTitle}},
		},
		XAxis: excelize.ChartAxis{
			Title: []excelize.RichTextRun{{Text: "时间"}},
		},
		Legend: excelize.ChartLegend{
			Position:      "bottom",
			ShowLegendKey: false,
		},
		PlotArea: excelize.ChartPlotArea{
			ShowBubbleSize:  true,
			ShowCatName:     false,
			ShowLeaderLines: false,
			ShowPercent:     false,
			ShowSerName:     false,
			ShowVal:         false,
		},
		Dimension: excelize.ChartDimension{
			Width:  960,
			Height: 480,
		},
		ShowBlanksAs: "gap",
	}); err != nil {
		return fmt.Errorf("adding chart: %w", err)
	}

	return nil
}

// cellName is a shorthand for excelize.CoordinatesToCellName
func cellName(col, row int) string {
	s, _ := excelize.CoordinatesToCellName(col, row)
	return s
}
