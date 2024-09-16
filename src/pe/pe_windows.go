package pe

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/hex"
	"fmt"
	"github.com/praetorian-inc/goffloader/src/coff"
	"github.com/praetorian-inc/goffloader/src/lighthouse"
	"io"
	"strings"
)

func decompress(data []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	var buf bytes.Buffer
	_, err = io.Copy(&buf, reader)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

//go:embed static/NoConsolation.x64.o.gz
var noConsolation []byte

// Fake the equivalent of running noconsolation
func RunExecutable(executableBytes []byte, args []string) (string, error) {
	decompressedBytes, _ := decompress(noConsolation)

	peName := "calc.exe"
	pePath := fmt.Sprintf("C:\\Windows\\System32\\%s", peName)

	updatedArgs := append([]string{pePath}, args...)

	argBytes, err := lighthouse.PackArgs([]string{
		"Z" + peName, // Unicode PE Name
		"z" + peName, // ANSI PE Name
		"Z" + pePath, // Unicode PE Path
		"b" + hex.EncodeToString(executableBytes), // The actual PE to load
		"z",                                  // for local PE loading, we don't need it
		"i0",                                 // not doing local loading
		"i60",                                // 60 second timeout
		"i0",                                 // no headers
		"Z" + strings.Join(updatedArgs, " "), // Unicode Args
		"z" + strings.Join(updatedArgs, " "), // ANSI Args
		"z",                                  // Invoke default entry point method
		"i0",                                 // not using unicode
		"i0",                                 // we don't want to disable output
		"i1",                                 // allocating a console so we can capture output
		"i0",                                 // don't need to worry about closing handles
		"i0",                                 // don't need to worry about freeing libraries
		"i1",                                 // don't need to worry about saving
		"i0",                                 // not listing PEs
		"z",                                  // not unloading any PEs
		"z",                                  // no need for us to have anything as our nick() for now
		"z" + "0",                            // timestamp doesn't matter
		"i0",                                 // linking to PEB
		"i0",                                 // unloading is fine
		"i0",                                 // do load all dependencies
		"z",                                  // load_all_deps_but DLL_A,DLL_B,DLL_C...
		"z",                                  // not using load_deps
		"z",                                  // not using search_paths
		"i1",                                 // running with -inthread
	})
	if err != nil {
		return "", fmt.Errorf("Failed to pack arguments: %s\n", err.Error())
	}

	return coff.Load(decompressedBytes, argBytes)
}
