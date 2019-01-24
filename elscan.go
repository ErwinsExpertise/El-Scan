package main

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
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

func main() {
	fmt.Println("El Scan - which is Spanish for \"The Scan\" ")

	infected := []string{}
	exploits := map[string]string{
		"eval_chr":             "/chr[\\s\r\n]*\\([\\s\r\n]*101[\\s\r\n]*\\)[\\s\r\n]*\\.[\\s\r\n]*chr[\\s\r\n]*\\([\\s\r\n]*118[\\s\r\n]*\\)[\\s\r\n]*\\.[\\s\r\n]*chr[\\s\r\n]*\\([\\s\r\n]*97[\\s\r\n]*\\)[\\s\r\n]*\\.[\\s\r\n]*chr[\\s\r\n]*\\([\\s\r\n]*108[\\s\r\n]*\\)/i",
		"align":                "/(\\\\$\\w+=[^;]*)*;\\\\$\\w+=@?\\\\$\\w+\\(/i",
		"b374k":                "/'ev'\\.'al'\\.'\\(\"\\?>/i",
		"weevely3":             "/\\\\$\\w=\\\\$[a-zA-Z]\\('',\\\\$\\w\\);\\\\$\\w\\(\\);/i",
		"c99_launcher":         "/;\\\\$\\w+\\(\\\\$\\w+(,\\s?\\\\$\\w+)+\\);/i",
		"too_many_chr":         "/(chr\\([\\d]+\\)\\.){8}/i",
		"concat":               "/(\\\\$[\\w\\[\\]\\'\\\"]+\\.[\n\r]*){10}/i",
		"var_as_func":          "/\\\\$_(GET|POST|COOKIE|REQUEST|SERVER)[\\s\r\n]*\\[[^\\]]+\\][\\s\r\n]*\\(/i",
		"extract_global":       "/extract\\([\\s\r\n]*\\\\$_(GET|POST|COOKIE|REQUEST|SERVER)/i",
		"escaped_path":         "/(x[0-9abcdef]{2}[a-z0-9.-\\/]{1,4}){4,}/i",
		"include_icon":         "/include\\(?[\\s\r\n]*(\\\"|\\')(.*?)(\\.|\\056\\0462E)(i|\\\\151|\\x69|\\105)(c|\\143\\099\\x63)(o|\\157\\111|\\x6f)(\\\"|\\')\\)?/mi", // Icon inclusion
		"backdoor_code":        "/eva1fYlbakBcVSir/i",
		"infected_comment":     "/\\/\\*[a-z0-9]{5}\\*\\//i",
		"hex_char":             "/\\[Xx](5[Ff])/i",
		"download_remote_code": "/echo\\s+file_get_contents[\\s\r\n]*\\([\\s\r\n]*base64_url_decode[\\s\r\n]*\\([\\s\r\n]*@*\\\\$_(GET|POST|SERVER|COOKIE|REQUEST)/i",
		"globals_concat":       "/\\\\$GLOBALS\\[\\\\$GLOBALS['[a-z0-9]{4,}'\\]\\[\\d+\\]\\.\\\\$GLOBALS\\['[a-z-0-9]{4,}'\\]\\[\\d+\\]./i",
		"globals_assign":       "/\\\\$GLOBALS\\['[a-z0-9]{5,}'\\] = \\\\$[a-z]+\\d+\\[\\d+\\]\\.\\\\$[a-z]+\\d+\\[\\d+\\]\\.\\\\$[a-z]+\\d+\\[\\d+\\]\\.\\\\$[a-z]+\\d+\\[\\d+\\]\\./i",
		"clever_include":       "/include[\\s\r\n]*\\([\\s\r\n]*[^\\.]+\\.(png|jpe?g|gif|bmp)/i",
		"basedir_bypass":       "/curl_init[\\s\r\n]*\\([\\s\r\n]*[\"']file:\\/\\//i",
		"basedir_bypass2":      "/file\\:file\\:\\/\\//i",
		"non_printable":        "/(function|return|base64_decode).{,256}[^\\x00-\\x1F\\x7F-\\xFF]{3}/i",
		"double_var":           "/\\\\${[\\s\r\n]*\\\\${/i",
		"double_var2":          "/\\${\\$[0-9a-zA-z]+}/i",
		"hex_var":              "/\\\\$\\{\\\"\\\\x/i",
		"register_function":    "/register_[a-z]+_function[\\s\r\n]*\\([\\s\r\n]*['\\\"][\\s\r\n]*(eval|assert|passthru|exec|include|system|shell_exec|`)/i", // https://github.com/nbs-system/php-malware-finder/issues/41
		"safemode_bypass":      "/\\x00\\/\\.\\.\\/|LD_PRELOAD/i",
		"ioncube_loader":       "/IonCube\\_loader/i",
	}

	searchDir, _ := os.Getwd()

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
			return
		}
		switch mode := fi.Mode(); {
		case mode.IsDir():
			break
		case mode.IsRegular():
			bSlice := readFile(file)
			content := byteToString(bSlice)

			for exp := range exploits {
				r := regexp.MustCompile(exploits[exp])
				matches := r.FindAllString(content, -1)

				if matches != nil {
					infected = append(infected, file)
				}
			}
		}

	}

	fmt.Printf("Here is a list of infected files: \n")
	for i := 0; i < len(infected); i++ {
		fmt.Println(infected[i])
	}

} //end main
