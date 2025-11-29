package honeypot_middleware

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
)

const (
	phpinfo__html        = `<%- files['phpinfo.html'] %>`
	wlwmanifest__xml     = `<%- files['wlwmanifest.xml'] %>`
	dot__env             = `<%- files['dot.env'] %>`
	blank                = ""
	htmlContentType      = "text/html; charset=UTF-8"
	plaintextContentType = "text/plain"
	xmlContentType       = "application/xml"
)

type Config struct {
	Verbose             bool     `json:"verbose" yaml:"verbose" toml:"verbose"`
	PhpInfoPatterns     []string `json:"phpInfoPatterns" yaml:"phpInfoPatterns" toml:"phpInfoPatterns"`
	ExecutionPatterns   []string `json:"executionPatterns" yaml:"executionPatterns" toml:"executionPatterns"`
	DotEnvPatterns      []string `json:"dotEnvPatterns" yaml:"dotEnvPatterns" toml:"dotEnvPatterns"`
	WlwmanifestPatterns []string `json:"wlwmanifestPatterns" yaml:"wlwmanifestPatterns" toml:"wlwmanifestPatterns"`
}

func CreateConfig() *Config {
	return &Config{
		Verbose:             true,
		PhpInfoPatterns:     []string{"/server-info\\.php$", "/(php_)?version\\.php$", "/phpinfo[0-9]?\\.php$", "/pi\\.php$", "/[^/]*\\.phpinfo$"},
		ExecutionPatterns:   []string{"/xmlrpc\\.php$", "/function\\.php$", "/bolt\\.php$", "/env\\.php$", "/userfuns\\.php$", "/postnews\\.php$", "/pwnd\\.php$", "/init-help/init\\.php$"},
		DotEnvPatterns:      []string{"\\.env$"},
		WlwmanifestPatterns: []string{"/wlwmanifest\\.xml$"},
	}
}

type HoneypotMiddleware struct {
	next                http.Handler
	Verbose             bool
	PhpInfoPatterns     []*regexp.Regexp
	ExecutionPatterns   []*regexp.Regexp
	DotEnvPatterns      []*regexp.Regexp
	WlwmanifestPatterns []*regexp.Regexp
}

func ReplaceReq(html string, path string) string {
	return strings.ReplaceAll(html, "%REQ_PATH%", path)
}

func LogBody(req *http.Request) error {
	if req.Body == nil {
		return nil
	}

	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		return err
	}

	var body = string(bodyBytes)

	if len(body) > 0 {
		fmt.Fprintf(os.Stdout, "[honeypot🟢] Body received: %s\n", body)
	}

	return nil
}

func (a *HoneypotMiddleware) SendResponse(rw http.ResponseWriter, req *http.Request, str string, contentType string) {
	rw.Header().Set("Content-type", contentType)
	rw.Header().Set("X-Robots-Tag", "noindex")
	rw.WriteHeader(200)
	rw.Write([]byte(ReplaceReq(str, req.URL.Path)))
	if a.Verbose {
		fmt.Fprintf(os.Stdout, "[honeypot🟢] serving %s:'%s%s' to %s UA: '%s'\n", req.Method, req.Host, req.RequestURI, req.RemoteAddr, req.UserAgent())
		var err = LogBody(req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[honeypot🔴] Failed to read request body: %s\n", err)
		}
	}
}

func IsMatch(req *http.Request, matchers []*regexp.Regexp) bool {
	var path string = req.URL.Path
	for j := 0; j < len(matchers); j++ {
		if matchers[j].MatchString(path) {
			return true
		}
	}
	return false
}

func (a *HoneypotMiddleware) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if IsMatch(req, a.PhpInfoPatterns) {
		rw.Header().Set("X-Powered-By", "PHP/5.3.29")
		rw.Header().Set("Server", "Apache/2.4.10 (Debian)")
		a.SendResponse(rw, req, phpinfo__html, htmlContentType)
		return
	}
	if IsMatch(req, a.ExecutionPatterns) {
		a.SendResponse(rw, req, blank, htmlContentType)
		return
	}
	if IsMatch(req, a.DotEnvPatterns) {
		a.SendResponse(rw, req, dot__env, plaintextContentType)
		return
	}
	if IsMatch(req, a.WlwmanifestPatterns) {
		a.SendResponse(rw, req, wlwmanifest__xml, xmlContentType)
		return
	}
	a.next.ServeHTTP(rw, req)
}

func MakeRegexSlice(patterns []string) ([]*regexp.Regexp, error) {
	var slice = make([]*regexp.Regexp, len(patterns))
	for j := range patterns {
		regex, e := regexp.Compile(patterns[j])
		if e == nil {
			slice[j] = regex
		} else {
			return nil, e
		}
	}
	return slice, nil
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	phpInfoPatterns, err := MakeRegexSlice(config.PhpInfoPatterns)
	if err != nil {
		return nil, err
	}
	executionPatterns, err := MakeRegexSlice(config.ExecutionPatterns)
	if err != nil {
		return nil, err
	}
	dotEnvPatterns, err := MakeRegexSlice(config.DotEnvPatterns)
	if err != nil {
		return nil, err
	}
	wlwmanifestPatterns, err := MakeRegexSlice(config.WlwmanifestPatterns)
	if err != nil {
		return nil, err
	}
	return &HoneypotMiddleware{
		next:                next,
		Verbose:             config.Verbose,
		PhpInfoPatterns:     phpInfoPatterns,
		ExecutionPatterns:   executionPatterns,
		DotEnvPatterns:      dotEnvPatterns,
		WlwmanifestPatterns: wlwmanifestPatterns,
	}, nil
}
