package main

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"

	pb "gopkg.in/cheggaaa/pb.v2"
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
	for item, _ := range m {
		result = append(result, item)
	}
	return result
}

func main() {
	fmt.Println("El Scan - which is Spanish for \"The Scan\" \n\n\n")

	fmt.Println("1 - Scan current directory recursivley")
	fmt.Println("2 - Clean files") // currently not implemented
	fmt.Println("3 - Help")
	var input int
	fmt.Scanln(&input)

	infected := []string{}
	exploits := map[string]string{
		"eval":         "(<\\?php|[;{}])[ \t]*@?(eval|preg_replace|system|assert|passthru|(pcntl_)?exec|shell_exec|call_user_func(_array)?)\\s*\\(",
		"eval_comment": "(eval|preg_replace|system|assert|passthru|(pcntl_)?exec|shell_exec|call_user_func(_array)?)\\/\\*[^\\*]*\\*\\/\\(",
		"b374k":        "'ev'.'al'",
		"align":        "(\\$\\w+=[^;]*)*;\\$\\w+=@?\\$\\w+\\(",
		"weevely3":     "\\$\\w=\\$[a-zA-Z]\\('',\\$\\w\\);\\$\\w\\(\\);",
		"c99_launcher": ";\\$\\w+\\(\\$\\w+(,\\s?\\$\\w+)+\\);",
		"nano":         "\\$[a-z0-9-_]+\\[[^]]+\\]\\(",
		"ninja":        "(.?)base64_decode[^;]+",
		"var_var":      "\\${\\$[0-9a-zA-z]+}",
		"chr":          "(chr\\([\\d]+\\)\\.){8}",
		"concat":       "(\\$[^\n\r]+\\.){5}",
		"con_space":    "(\\$[^\n\r]+\\. ){5}",
		"var_func":     "\\$_(GET|POST|COOKIE|REQUEST|SERVER)\\s*\\[[^\\]]+\\]\\s*\\(",
		"base_by":      "/curl_init\\s*\\(\\s*[\"']file:\\/\\//",
		"base_by2":     "file:file:///",
		"exec":         "\b(eval|assert|passthru|exec|include|system|pcntl_exec|shell_exec|base64_decode|`|array_map|ob_start|call_user_func(_array)?)\\s*\\(\\s*(base64_decode|php:\\/\\/input|str_rot13|gz(inflate|uncompress)|getenv|pack|\\?\\$_(GET|REQUEST|POST|COOKIE|SERVER))",
		"ini":          "ini_(get|set|restore)\\s*\\(\\s*['\"](safe_mode|open_basedir|disable_(function|classe)s|safe_mode_exec_dir|safe_mode_include_dir|register_globals|allow_url_include)/ nocase",
		"includes":     "include\\s*\\(\\s*[^\\.]+\\.(png|jpg|gif|bmp)",
	}

	strip := map[string]string{
		"com": "/\\/\\*.*?\\*\\/|\\/\\/.*?\n|\\#.*?\n/i",
		"eva": "/(\\'|\\\")[\\s\r\n]*\\.[\\s\r\n]*('|\")/i",
	}

	switch input {

	case 1:
		searchDir, _ := os.Getwd()

		fileList := []string{}
		err := filepath.Walk(searchDir, func(path string, f os.FileInfo, err error) error {
			fileList = append(fileList, path)
			return nil
		})
		if err != nil {
			fmt.Print(err)
		}
		bar := pb.StartNew(len(fileList))

		for _, file := range fileList {
			bar.Increment()
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

				for stri := range strip {
					str := stripFile(content, "", strip[stri])
					for exp := range exploits {
						r := regexp.MustCompile(exploits[exp])
						matches := r.FindAllString(str, -1)

						if matches != nil {
							infected = append(infected, file+" - "+exp)
							break
						}
					}
				}
			}

		}
		bar.Finish()
		infect := RemoveDuplicatesFromSlice(infected)
		fmt.Printf("Here is a list of infected/suspicious files: \n")
		for i := 0; i < len(infect); i++ {
			fmt.Println(infect[i])
		}
		break
	case 2:
		fmt.Println("Not yet implemented")
		break
	case 3:
		fmt.Println("This tool is made to scan php files for malicious code")
		break

	} //end switch

} //end main

