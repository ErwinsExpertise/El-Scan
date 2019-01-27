package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
)

type checksum map[string]interface{}

func getVersion() string {
	file, err := os.Open("wp-includes/version.php")
	if err != nil {
		log.Panic(err)
	}

	scanner := bufio.NewScanner(file)
	var vSlice []string
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), "$wp_version") {
			ver := strings.Replace(scanner.Text(), "'", "", -1)
			ver = strings.Replace(ver, ";", "", -1)
			vSlice = strings.Split(ver, "=")
		} // else keep going
	}
	return vSlice[1]

}

func (c *checksum) getWPMD5(version string) {
	url := "https://api.wordpress.org/core/checksums/1.0/?version=" + version

	client := &http.Client{}

	Req, _ := http.NewRequest("GET", url, nil)
	Resp, _ := client.Do(Req)
	body, _ := ioutil.ReadAll(Resp.Body)

	json.Unmarshal(body, &c)

}

func (c checksum) printMD5() {
	fmt.Printf("/n Here: %+q /n", c)
}
