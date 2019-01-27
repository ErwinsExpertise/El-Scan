package main

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
	"strings"

	pb "gopkg.in/cheggaaa/pb.v2"
)

func main() {
	fmt.Println("El Scan - which is Spanish for \"The Scan\" \n\nInitializing, please wait...  \n\n\n")
	infected := []string{}
	searchDir, _ := os.Getwd()
	fileList := getFileTree()

	fmt.Println("1 - Scan for known malicious code")
	fmt.Println("2 - Scan for known signatures")
	fmt.Println("3 - Scan WordPress files for checksum")
	fmt.Println("4 - Help\n")
	var input int
	fmt.Scanln(&input)

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
	bar := pb.StartNew(len(fileList))

	switch input {

	case 1:

		for _, file := range fileList {
			bar.Increment()
			bSlice := readFile(file)
			content := byteToString(bSlice)

			for stri := range strip {
				str := stripFile(content, "", strip[stri])
				for exp := range exploits {
					r := regexp.MustCompile(exploits[exp])
					matches := r.FindAllString(str, -1)

					if matches != nil {
						infected = append(infected, file+" - "+exp)
					}
				}
			}
		}
		bar.Finish()
		printInfected(infected)
		break
	case 2: // This is for signature scanning
		sign := sigs{}
		sig := sign.unloadSigs("signatures.tgz")

		for _, file := range fileList {
			bar.Increment()

			bSlice := readFile(file)
			oCheck := getCheckSum(bSlice)

			for si := range sig {
				md := md5.Sum([]byte(sig[si]))

				if oCheck == md {
					infected = append(infected, file)
				}
			}
		}

		bar.Finish()
		printInfected(infected)
		break

	case 3:
		checkMD := checksum{}
		var mds map[string]interface{}
		version := getVersion()[1:]
		checkMD.getWPMD5(version)
		convert, ok := checkMD["checksums"].(map[string]interface{})
		if ok {
			mds = convert[version].(map[string]interface{})
		}

		for _, file := range fileList {
			bar.Increment()
			loc := strings.Replace(file, searchDir, "", -1)
			loc = strings.Replace(loc, "\\", "/", -1)
			md := mds[loc[1:]]

			f, err := os.Open(file)
			if err != nil {
				log.Fatal(err)
			}
			defer f.Close()

			oCheck := md5.New()
			if _, err := io.Copy(oCheck, f); err != nil {
				log.Fatal(err)
			}
			oMD5 := hex.EncodeToString(oCheck.Sum(nil))
			if _, ok := mds[loc[1:]]; ok {
				if oMD5 != md {
					infected = append(infected, file)
				}
			}

		}
		bar.Finish()
		printInfected(infected)
		break
	case 4:
		fmt.Println("This tool is made to scan php files for malicious code")
		break
	default:
		fmt.Println("Unknown option - Please select a valid option")
		break

	} //end switch

} //end main
