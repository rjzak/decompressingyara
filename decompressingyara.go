package main

// #cgo LDFLAGS: /usr/local/lib/libyara.a -lcrypto -lmagic -ljansson -lm
// #include <yara.h>
import "C"

import (
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"github.com/hillu/go-yara"
	"github.com/ulikunitz/xz"
)

func DecompressXZ(buffer []byte) ([]byte, error) {
	r, err := xz.NewReader(bytes.NewBuffer(buffer))
	if err != nil {
		return make([]byte, 0), err
	}

	data, err := ioutil.ReadAll(r)
	if err != nil {
		return data, err
	}

	return data, nil
}

func DecompressBzip(buffer []byte) ([]byte, error) {
	bz := bzip2.NewReader(bytes.NewBuffer(buffer))
	data, err := ioutil.ReadAll(bz)
	if err != nil {
		return data, err
	}

	return data, nil
}

func DecompressGzip(buffer []byte) ([]byte, error) {
	gr, err := gzip.NewReader(bytes.NewBuffer(buffer))
	if err != nil {
		return make([]byte, 0), err
	}

	defer gr.Close()

	data, err := ioutil.ReadAll(gr)
	if err != nil {
		return make([]byte, 0), err
	}

	return data, nil
}

func DecompressFile(filePath string) ([]byte, error) {
	var fileBuffer []byte
	var err error
	fileContents, err := ioutil.ReadFile(filePath)
	if err != nil {
		return fileBuffer, err
	}

	if bytes.Compare(fileContents[:2], []byte{0x1f, 0x8b}) == 0 {
		fileBuffer, err = DecompressGzip(fileContents)
		if err != nil {
			return fileBuffer, err
		}
	} else {
		if bytes.Compare(fileContents[:3], []byte{0x42, 0x5a, 0x68}) == 0 {
			fileBuffer, err = DecompressBzip(fileContents)
			if err != nil {
				return fileBuffer, err
			}
		} else {
			if bytes.Compare(fileContents[:6], []byte{0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00}) == 0 {
				fileBuffer, err = DecompressXZ(fileContents)
				if err != nil {
					return fileBuffer, err
				}
			} else {
				fileBuffer = fileContents
			}
		}
	}

	return fileBuffer, nil
}

func MatchSamples(samplesDir string, rules *yara.Rules) {
	err := filepath.Walk(samplesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() {
			fileContents, err := DecompressFile(path)
			if err != nil {
				return nil
			}

			matches, err := rules.ScanMem(fileContents, 0, 0)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error scanning %s with Yara: %v\n", path, err)
				return err
			}

			for _, match := range matches {
				fmt.Printf("%s: %s matches.\n", match.Rule, path)
			}
		}

		return nil
	});

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error walking %s: %v\n", samplesDir, err)
	}
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <Directory> <Yara File>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Yara version: %s\n", C.YR_VERSION)
		fmt.Fprintf(os.Stderr, "Go version: %s\n", runtime.Version())
		os.Exit(1)
	}

	samplesDirectory := os.Args[1]
	yaraFile := os.Args[2]
	yaraCompiler, err := yara.NewCompiler()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize YARA compiler: %v\n", err)
		os.Exit(10)
	}

	f, err := os.Open(yaraFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed open Yara file %s: %v\n", yaraFile, err)
		os.Exit(10)
	}
	defer f.Close()

	err = yaraCompiler.AddFile(f, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed parse Yara file %s: %v\n", yaraFile, err)
		os.Exit(10)
	}

	yaraRules, err := yaraCompiler.GetRules()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed compile Yara rules: %v\n", err)
		os.Exit(10)
	}

	MatchSamples(samplesDirectory, yaraRules)
}
