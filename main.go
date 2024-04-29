package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"flag"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

type fileInfo struct {
	path string
	size int64
}

func isRegularFile(info fs.FileInfo) bool {
	return info.Mode()&os.ModeType == 0
}

func getFiles(out io.Writer, path string, skipZeroes bool, patterns []string) ([]fileInfo, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	results := make([]fileInfo, 0)
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			fmt.Fprintln(out, "ERROR:", err)
			continue
		}
		if info.IsDir() {
			files, err := getFiles(out, filepath.Join(path, info.Name()), skipZeroes, patterns)
			if err != nil {
				fmt.Fprintln(out, "ERROR:", err)
				continue
			}
			results = append(results, files...)
		} else {
			if !isRegularFile(info) {
				continue
			}
			if skipZeroes && info.Size() == 0 {
				continue
			}

			path := filepath.Join(path, info.Name())
			if len(patterns) != 0 {
				hasMatches := false
				for i := range patterns {
					matched, err := filepath.Match(patterns[i], info.Name())
					if err != nil {
						return results, err
					}
					if !matched {
						hasMatches = true
						break
					}

				}
				if !hasMatches {
					continue
				}
			}
			info := fileInfo{path: path, size: info.Size()}

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

func getHash(file fileInfo, hashFunc string, copySize int64) (string, error) {
	f, err := os.Open(file.path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	var h hash.Hash
	switch hashFunc {
	case "sha1":
		h = sha1.New()
	case "sha256":
		h = sha256.New()
	case "sha512":
		h = sha512.New()
	default:
		h = md5.New()
	}
	if copySize == -1 {
		if _, err := io.Copy(h, f); err != nil {
			return "", err
		}
	} else {
		copySize = min(copySize, file.size)
		if _, err := io.CopyN(h, f, copySize); err != nil {
			return "", err
		}
	}
	hashsum := h.Sum(nil)
	return string(hashsum), nil
}

const hashProbeSize = 4096

func getDoublesByHashsum(out io.Writer, candidates []fileInfo, hashFunc string, numBytes int64) [][]fileInfo {
	hashes := make(map[string][]fileInfo)
	for _, file := range candidates {
		hash, err := getHash(file, hashFunc, numBytes)
		if err != nil {
			fmt.Fprintln(out, "ERROR", err)
		}
		if _, exists := hashes[hash]; !exists {
			hashes[hash] = make([]fileInfo, 0)
		}
		hashes[hash] = append(hashes[hash], file)
	}

	doublesGroups := make([][]fileInfo, 0)
	for hash := range hashes {
		if len(hashes[hash]) == 1 {
			continue
		}
		doublesGroups = append(doublesGroups, hashes[hash])
	}
	return doublesGroups
}

func getDoubles(out io.Writer, candidates []fileInfo, hashFunc string) [][]fileInfo {
	potentialDoubles := getDoublesByHashsum(out, candidates, hashFunc, hashProbeSize)
	if len(potentialDoubles) == 0 {
		return potentialDoubles
	}
	result := make([][]fileInfo, 0)
	for i := range potentialDoubles {
		group := potentialDoubles[i]
		doubles := getDoublesByHashsum(out, group, hashFunc, -1)
		if len(doubles) > 0 {
			result = append(result, doubles...)
		}
	}
	return result
}

func groupSize(g []fileInfo) int64 {
	var sum int64 = 0
	for i := range g {
		sum += g[i].size
	}
	return sum
}

func sortResults(doubles [][]fileInfo) [][]fileInfo {
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

func printDoubles(out io.Writer, doubles [][]fileInfo, showSizes bool, calcWastedSpace bool) {
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
			if showSizes {
				readableSize := convertFileSizeToHumanReadable(file.size)
				fmt.Fprintf(out, "%s\t%s\n", readableSize, file.path)
			} else {
				fmt.Fprintf(out, "%s\n", file.path)
			}
		}
	}

	if calcWastedSpace {
		wastedSpace := calculateWastedSpace(results)
		fmt.Fprintf(out, "\nPotential wasted disk space: %s\n", convertFileSizeToHumanReadable(wastedSpace))
	}
}

type options struct {
	showSizes       bool
	calcWastedSpace bool
	skipZeroes      bool
	hashFunc        string
	patterns        []string
}

func run(out io.Writer, errOut io.Writer, paths []string, o options) {
	files := make([]fileInfo, 0)
	fileSet := make(map[string]struct{})
	for _, path := range paths {
		pathFiles, err := getFiles(errOut, path, o.skipZeroes, o.patterns)
		if err != nil {
			fmt.Fprintln(errOut, err)
		}

		for i := range pathFiles {
			filePath := pathFiles[i].path
			if _, exists := fileSet[filePath]; !exists {
				files = append(files, pathFiles[i])
			}
		}
	}

	sizeDoubles := getDoublesBySize(files)
	doubles := make([][]fileInfo, 0)
	for size := range sizeDoubles {
		doublesCandidates := sizeDoubles[size]
		foundDoubles := getDoubles(errOut, doublesCandidates, o.hashFunc)
		if len(foundDoubles) > 0 {
			doubles = append(doubles, foundDoubles...)
		}

	}

	printDoubles(out, doubles, o.showSizes, o.calcWastedSpace)
}

type patterns []string

func (p *patterns) String() string {
	return strings.Join(*p, " ")
}

func (p *patterns) Set(s string) error {
	*p = append(*p, s)
	return nil
}

func main() {
	var (
		showSizes       bool
		suppressErrors  bool
		calcWastedSpace bool
		skipZeroes      bool
		hashFunc        string
		patternList     patterns
	)

	flag.BoolVar(&showSizes, "s", true, "show file sizes (shorthand)")
	flag.BoolVar(&showSizes, "show-sizes", true, "show file sizes")
	flag.BoolVar(&suppressErrors, "no-errors", false, "suppress error messages")
	flag.BoolVar(&calcWastedSpace, "calc", true, "calculate wasted space")
	flag.BoolVar(&skipZeroes, "skip-zero", true, "skip zero-sized files")
	flag.StringVar(&hashFunc, "hash-func", "md5", "hash function (md5|sha1|sha256|sha512)")
	flag.Var(&patternList, "pattern", "pattern for file names (https://pkg.go.dev/path/filepath#Match)")
	flag.Var(&patternList, "p", "pattern for file names (https://pkg.go.dev/path/filepath#Match) (shorthand)")

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "doubles: find duplicate files on given paths\n")
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of doubles:\n")
		fmt.Fprintf(flag.CommandLine.Output(), "doubles [OPTIONS] PATH_1 PATH_2 ... PATH_N\n")
		fmt.Fprintf(flag.CommandLine.Output(), "Options:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	paths := flag.Args()
	if len(paths) == 0 {
		paths = []string{"."}
	}

	out := os.Stdout
	var errOut io.Writer
	if suppressErrors {
		errOut = io.Discard
	} else {
		errOut = os.Stderr
	}
	run(out, errOut, paths, options{
		showSizes:       showSizes,
		calcWastedSpace: calcWastedSpace,
		skipZeroes:      skipZeroes,
		hashFunc:        hashFunc,
		patterns:        patternList,
	})
}
