package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"text/template"
	"time"
)

type CVEItem struct {
	CVEID       string    `json:"id"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	Published   time.Time `json:"published"`
}

func main() {
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	http.HandleFunc("/", serveIndex)
	http.HandleFunc("/fetch-cves", serveCVEs)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func serveIndex(w http.ResponseWriter, r *http.Request) {
	t, err := template.ParseFiles("templates/index.html")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Println("Error parsing template:", err)
		return
	}
	if err := t.Execute(w, nil); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Println("Error executing template:", err)
	}
}

func serveCVEs(w http.ResponseWriter, r *http.Request) {
	startIndex, err := strconv.Atoi(r.URL.Query().Get("start"))
	if err != nil {
		startIndex = 0
	}
	cves, err := fetchCVEs(startIndex)
	if err != nil {
		http.Error(w, "Failed to fetch CVEs", http.StatusInternalServerError)
		log.Println("Error fetching CVEs:", err)
		return
	}
	log.Printf("Fetched %d CVEs\n", len(cves))
	t, err := template.New("cve").Funcs(template.FuncMap{
		"lower": strings.ToLower,
	}).Parse(cveTemplate)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Println("Error parsing CVE template:", err)
		return
	}
	if err := t.Execute(w, cves); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Println("Error executing CVE template:", err)
	}
}

func fetchCVEs(startIndex int) ([]CVEItem, error) {
	url := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=20&startIndex=%d", startIndex)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("received non-200 response code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var data struct {
		Vulnerabilities []struct {
			CVE struct {
				ID          string `json:"id"`
				Description struct {
					DescriptionData []struct {
						Value string `json:"value"`
					} `json:"descriptions"`
				} `json:"cve"`
				Metrics struct {
					CvssMetricV31 []struct {
						CvssData struct {
							BaseSeverity string `json:"baseSeverity"`
						} `json:"cvssData"`
					} `json:"cvssMetricV31"`
				} `json:"metrics"`
				Published string `json:"published"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}

	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("error unmarshaling JSON: %w", err)
	}

	cves := make([]CVEItem, 0, len(data.Vulnerabilities))
	for _, item := range data.Vulnerabilities {
		desc := item.CVE.Description.DescriptionData
		if len(desc) == 0 {
			continue
		}
		severity := ""
		if len(item.CVE.Metrics.CvssMetricV31) > 0 {
			severity = item.CVE.Metrics.CvssMetricV31[0].CvssData.BaseSeverity
		}
		published, err := time.Parse(time.RFC3339, item.CVE.Published)
		if err != nil {
			log.Println("Error parsing date:", err)
			continue
		}
		cves = append(cves, CVEItem{
			CVEID:       item.CVE.ID,
			Description: desc[0].Value,
			Severity:    severity,
			Published:   published,
		})
	}

	sort.Slice(cves, func(i, j int) bool {
		return cves[i].Published.After(cves[j].Published)
	})

	return cves, nil
}

const cveTemplate = `
{{range .}}
<div class="card">
	<h2>{{.CVEID}}</h2>
	<p>{{.Description}}</p>
	<a href="https://nvd.nist.gov/vuln/detail/{{.CVEID}}" target="_blank" class="read-more">Read More</a>
	<span class="severity {{.Severity | lower}}">{{.Severity}}</span>
</div>
{{end}}
`
