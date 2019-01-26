package main

import (
	"crypto/md5"
	"encoding/hex"
	"io/ioutil"
	"log"
	"regexp"
)

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
