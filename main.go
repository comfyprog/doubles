package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
)

type fileInfo struct {
	path string
	size int64
}

func isRegularFile(info fs.FileInfo) bool {
	return info.Mode()&os.ModeType == 0
}

func getFiles(path string) ([]fileInfo, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	results := make([]fileInfo, 0)
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			fmt.Fprintln(os.Stderr, "ERROR:", err)
			continue
		}
		if info.IsDir() {
			files, err := getFiles(filepath.Join(path, info.Name()))
			if err != nil {
				fmt.Fprintln(os.Stderr, "ERROR:", err)
				continue
			}
			results = append(results, files...)
		} else {
			if !isRegularFile(info) {
				continue
			}
			info := fileInfo{path: filepath.Join(path, info.Name()), size: info.Size()}

			results = append(results, info)
		}
	}
	return results, nil
}

func getDoublesBySize(files []fileInfo) map[int64][]fileInfo {
	result := make(map[int64][]fileInfo)
	for i := range files {
		size := files[i].size
		if _, exists := result[size]; !exists {
			result[size] = make([]fileInfo, 0)
		}
		result[size] = append(result[size], files[i])
	}

	for size, fileList := range result {
		if len(fileList) == 1 {
			delete(result, size)
		}
	}
	return result
}

func getSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	hashsum := h.Sum(nil)
	return string(hashsum), nil
}

func getDoublesByHashsum(files map[int64][]fileInfo) map[string][]fileInfo {
	hashes := make(map[string][]fileInfo)
	for _, fileList := range files {
		for _, file := range fileList {
			hash, err := getSHA256(file.path)
			if err != nil {
				fmt.Fprintln(os.Stderr, "ERROR", err)
			}
			if _, exists := hashes[hash]; !exists {
				hashes[hash] = make([]fileInfo, 0)
			}
			hashes[hash] = append(hashes[hash], file)
		}
	}

	for hash := range hashes {
		if len(hashes[hash]) == 1 {
			delete(hashes, hash)
		}
	}
	return hashes
}

func groupSize(g []fileInfo) int64 {
	var sum int64 = 0
	for i := range g {
		sum += g[i].size
	}
	return sum
}

func sortResults(doubles map[string][]fileInfo) [][]fileInfo {
	results := make([][]fileInfo, 0, len(doubles))
	for k := range doubles {
		group := doubles[k]
		slices.SortFunc(group, func(a, b fileInfo) int {
			if a.path > b.path {
				return 1
			} else if a.path < b.path {
				return -1
			} else {
				return 0
			}
		})
		results = append(results, group)
	}

	slices.SortFunc(results, func(g1, g2 []fileInfo) int {
		s1 := groupSize(g1)
		s2 := groupSize(g2)
		if s1 > s2 {
			return 1
		} else if s1 < s2 {
			return -1
		} else {
			return 0
		}
	})

	return results
}

func calculateWastedSpace(doubles [][]fileInfo) int64 {
	var result int64 = 0
	for i := range doubles {
		result += doubles[i][0].size * int64(len(doubles[i])-1)
	}
	return result
}

const (
	kilo = 1 << 10
	mega = 1 << 20
	giga = 1 << 30
	tera = 1 << 40
	peta = 1 << 50
)

func convertFileSizeToHumanReadable(size int64) string {
	var divisor int64
	var suffix string

	switch {
	case size > peta:
		suffix = "PB"
		divisor = peta
	case size > tera:
		suffix = "TB"
		divisor = tera
	case size > giga:
		suffix = "GB"
		divisor = giga
	case size > mega:
		suffix = "MB"
		divisor = mega
	case size > kilo:
		suffix = "KB"
		divisor = kilo
	default:
		divisor = 1
		suffix = ""
	}

	if divisor != 1 {
		shortSize := float64(size) / float64(divisor)
		return fmt.Sprintf("%.1f%s", shortSize, suffix)
	}
	return fmt.Sprintf("%d bytes", size)
}

func printDoubles(out io.Writer, doubles map[string][]fileInfo) {
	if len(doubles) == 0 {
		fmt.Fprintln(out, "no duplicates found")
		return
	}

	results := sortResults(doubles)

	for i := range results {
		if i > 0 {
			fmt.Fprintf(out, "\n\n")
		}
		group := results[i]
		for _, file := range group {
			readableSize := convertFileSizeToHumanReadable(file.size)
			fmt.Fprintf(out, "%s\t%s\n", readableSize, file.path)
		}
	}

	wastedSpace := calculateWastedSpace(results)
	fmt.Fprintf(out, "\nPotential wasted disk space: %s\n", convertFileSizeToHumanReadable(wastedSpace))
}

func main() {
	path := os.Args[1]
	files, err := getFiles(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}

	sizeDoubles := getDoublesBySize(files)
	doubles := getDoublesByHashsum(sizeDoubles)
	printDoubles(os.Stdout, doubles)
}