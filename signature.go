package main

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"os"
)

type sig struct {
	Match string `json:"Match"`
}

type sigs struct {
	Parts []sig `json:"Parts"`
}

func (s sigs) toString() []string {
	var str []string
	for i := 0; i < len(s.Parts); i++ {
		str = append(str, s.Parts[i].Match)
	}

	return str
}

func (s *sigs) unloadSigs(filename string) []string {
	var signatures []string

	file, err := os.Open(filename)
	if err != nil {
		log.Panic("Unable to retrieve signatures")
	}

	unz, err2 := gzip.NewReader(file)
	if err2 != nil {
		log.Panic(err2)
	}

	defer unz.Close()

	tr := tar.NewReader(unz)
	i := 0
	for {
		i++
		head, err3 := tr.Next()

		switch {
		case err3 == io.EOF:
			return signatures
		case err3 != nil:
			break
		case head == nil:
			continue
		}
		tmp := os.TempDir()

		switch head.Typeflag {
		case tar.TypeDir:
			if _, err4 := os.Stat(tmp); err4 != nil {
				if err4 := os.MkdirAll(tmp, 0755); err4 != nil {
					break
				}
			}

		case tar.TypeReg:
			f, _ := ioutil.ReadAll(tr)
			json.Unmarshal(f, &s)
			sigl := s.toString()
			for i := 0; i < len(sigl); i++ {
				signatures = append(signatures, sigl[i])
			}
		}

	} //end for

} //end unloadSigs
