package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"text/template"
)

type CVEItem struct {
	CVEID       string `json:"cve_id"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
}

func main() {
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		t, err := template.ParseFiles("templates/index.html")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		t.Execute(w, nil)
	})

	http.HandleFunc("/fetch-cves", func(w http.ResponseWriter, r *http.Request) {
		cves, err := fetchCVEs()
		if err != nil {
			http.Error(w, "Failed to fetch CVEs", http.StatusInternalServerError)
			return
		}
		t, err := template.New("cve").Funcs(template.FuncMap{
			"lower": strings.ToLower,
		}).Parse(`
		{{range .}}
		<div class="card">
			<h2>{{.CVEID}}</h2>
			<p>{{.Description}}</p>
			<a href="https://nvd.nist.gov/vuln/detail/{{.CVEID}}" target="_blank" class="read-more">Read More</a>
			<span class="severity {{.Severity | lower}}">{{.Severity}}</span>
		</div>
		{{end}}`)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		t.Execute(w, cves)
	})

	log.Fatal(http.ListenAndServe(":6969", nil))
}

func fetchCVEs() ([]CVEItem, error) {
	resp, err := http.Get("https://services.nvd.nist.gov/rest/json/cves/1.0")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var data struct {
		Result struct {
			CVEItems []struct {
				CVE struct {
					CVEDataMeta struct {
						ID string `json:"ID"`
					} `json:"CVE_data_meta"`
					Description struct {
						DescriptionData []struct {
							Value string `json:"value"`
						} `json:"description_data"`
					} `json:"description"`
				} `json:"cve"`
				Impact struct {
					BaseMetricV3 struct {
						CVSSV3 struct {
							BaseSeverity string `json:"baseSeverity"`
						} `json:"cvssV3"`
					} `json:"baseMetricV3"`
				} `json:"impact"`
			} `json:"CVE_Items"`
		} `json:"result"`
	}

	err = json.Unmarshal(body, &data)
	if err != nil {
		return nil, err
	}

	var cves []CVEItem
	for _, item := range data.Result.CVEItems {
		cves = append(cves, CVEItem{
			CVEID:       item.CVE.CVEDataMeta.ID,
			Description: item.CVE.Description.DescriptionData[0].Value,
			Severity:    item.Impact.BaseMetricV3.CVSSV3.BaseSeverity,
		})
	}

	return cves, nil
}
