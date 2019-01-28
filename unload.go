package main

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"
)

type Infected []string

func readFile(filename string) []byte {
	file, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}
	return file
} //end readFile

func byteToString(byteSlice []byte) string {
	str := string(byteSlice)
	return str
} //end byteToString

func stripFile(content string, replace string, reg string) string {
	var r = regexp.MustCompile(reg)

	str := r.ReplaceAllString(content, replace)

	return str
} //end stripFile

func decodeHex(content string) []byte {
	hexByte, err := hex.DecodeString(content)
	if err != nil {
		log.Fatal(err)
	}

	return hexByte
} //end decodeHex

func RemoveDuplicatesFromSlice(s []string) []string {
	m := make(map[string]bool)
	for _, item := range s {
		if _, ok := m[item]; ok {
		} else {
			m[item] = true
		}
	}

	var result []string
	for item := range m {
		result = append(result, item)
	}
	return result
}

func getCheckSum(byt []byte) [16]byte {
	return md5.Sum(byt)
}

func getFileTree() []string {
	searchDir, _ := os.Getwd()
	files := []string{}

	fileList := []string{}
	err := filepath.Walk(searchDir, func(path string, f os.FileInfo, err error) error {
		fileList = append(fileList, path)
		return nil
	})
	if err != nil {
		fmt.Print(err)
	}

	for _, file := range fileList {
		fi, err2 := os.Stat(file)
		if err2 != nil {
			fmt.Println(err)
		}
		switch mode := fi.Mode(); {
		case mode.IsDir():
			break
		case mode.IsRegular():
			files = append(files, file)
		}

	}
	return files
}

func printInfected(in []string) {

	RemoveDuplicatesFromSlice(in)
	fmt.Printf("\nThere was %v suspicious files found.\n\nList of infected/suspicious files: \n", len(in))
	for i := 0; i < len(in); i++ {
		fmt.Println(in[i])
	}
}
