package honeypot_middleware

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

const (
	phpinfo__html             = `<%- files['phpinfo.html'] %>`
	wlwmanifest__xml          = `<%- files['wlwmanifest.xml'] %>`
	xmlrpc_get                = `<%- files['xmlrpc.get.txt'] %>`
	xmlrpc_post_getUserBlogs  = `<%- files['xmlrpc.post-get-user-blogs.xml'] %>`
	xmlrpc_post_incorrect     = `<%- files['xmlrpc.post-incorrect.xml'] %>`
	xmlrpc_post_newPost       = `<%- files['xmlrpc.post.new-post.xml'] %>`
	xmlrpc_post_notWellFormed = `<%- files['xmlrpc.post.not-well-formed.xml'] %>`
	dot__env                  = `<%- files['dot.env'] %>`
	blank                     = ""
	htmlContentType           = "text/html; charset=UTF-8"
	plaintextContentType      = "text/plain;charset=UTF-8"
	xmlContentType            = "text/xml; charset=UTF-8"
)

type Config struct {
	Verbose             bool     `json:"verbose" yaml:"verbose" toml:"verbose"`
	TrustProxy          bool     `json:"trustProxy" yaml:"TrustProxy" toml:"TrustProxy"`
	TrustCF             bool     `json:"trustCF" yaml:"trustCF" toml:"trustCF"`
	PhpInfoPatterns     []string `json:"phpInfoPatterns" yaml:"phpInfoPatterns" toml:"phpInfoPatterns"`
	ExecutionPatterns   []string `json:"executionPatterns" yaml:"executionPatterns" toml:"executionPatterns"`
	XmlRpcPatterns      []string `json:"xmlRpcPatterns" yaml:"xmlRpcPatterns" toml:"xmlRpcPatterns"`
	DotEnvPatterns      []string `json:"dotEnvPatterns" yaml:"dotEnvPatterns" toml:"dotEnvPatterns"`
	WlwmanifestPatterns []string `json:"wlwmanifestPatterns" yaml:"wlwmanifestPatterns" toml:"wlwmanifestPatterns"`
}

func CreateConfig() *Config {
	return &Config{
		Verbose:             true,
		TrustProxy:          false,
		TrustCF:             false,
		PhpInfoPatterns:     []string{"/server-info\\.php$", "/(php_)?version\\.php$", "/phpinfo[0-9]?\\.php$", "/pi\\.php$", "/[^/]*\\.phpinfo$", "/tmp\\.php$", "/php\\.php$"},
		ExecutionPatterns:   []string{"/function\\.php$", "/bolt\\.php$", "/env\\.php$", "/userfuns\\.php$", "/postnews\\.php$", "/pwnd\\.php$", "/init-help/init\\.php$", "/chosen\\.php$", "/rk2\\.php$", "/atomlib\\.php$", "/up\\.php$"},
		XmlRpcPatterns:      []string{"/xmlrpc\\.php$"},
		DotEnvPatterns:      []string{"\\.env$"},
		WlwmanifestPatterns: []string{"/wlwmanifest\\.xml$"},
	}
}

type HoneypotMiddleware struct {
	next                http.Handler
	Verbose             bool
	TrustProxy          bool
	TrustCF             bool
	PhpInfoPatterns     []*regexp.Regexp
	ExecutionPatterns   []*regexp.Regexp
	XmlRpcPatterns      []*regexp.Regexp
	DotEnvPatterns      []*regexp.Regexp
	WlwmanifestPatterns []*regexp.Regexp
}

func (a *HoneypotMiddleware) getBaseURL(req *http.Request) string {
	scheme := "http"
	if req.TLS != nil {
		scheme = "https"
	}

	if proto := req.Header.Get("X-Forwarded-Proto"); proto != "" && a.TrustProxy {
		scheme = proto
	}

	return scheme + "://" + req.Host
}

func (a *HoneypotMiddleware) ReplaceRuntimeVariables(html string, req *http.Request) string {
	baseUrl := a.getBaseURL(req)
	full := baseUrl + req.URL.Path
	reqPath := strings.ReplaceAll(html, "%REQ_PATH%", req.URL.Path)
	reqHost := strings.ReplaceAll(reqPath, "%REQ_HOST%", req.Host)
	reqBaseUrl := strings.ReplaceAll(reqHost, "%REQ_BASE_URL%", baseUrl)
	reqFull := strings.ReplaceAll(reqBaseUrl, "%REQ_FULL%", full)
	return reqFull
}

func GetBody(req *http.Request) (string, error) {
	if req.Body == nil {
		return "", nil
	}
	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		return "", err
	}

	return string(bodyBytes), nil
}

func LogBody(req *http.Request) (string, error) {
	body, err := GetBody(req)
	if err != nil {
		return "", err
	}

	if len(body) > 0 {
		fmt.Fprintf(os.Stdout, "[honeypot🟢] Body received: %s\n", body)
	}

	return body, nil
}

func (a *HoneypotMiddleware) GetRemoteAddr(req *http.Request) string {
	if ip := req.Header.Get("CF-Connecting-IP"); ip != "" && a.TrustCF {
		return ip
	}
	return req.RemoteAddr
}

type SendResponseArgs struct {
	ResponseWriter http.ResponseWriter
	Request        *http.Request
	Body           string
	ContentType    string
	ResponseCode   int
}

func CreateSendResponseArgs() SendResponseArgs {
	return SendResponseArgs{
		Body:         blank,
		ContentType:  htmlContentType,
		ResponseCode: 200,
	}
}

func (a *HoneypotMiddleware) SendResponse(args SendResponseArgs) {
	args.ResponseWriter.Header().Set("Content-type", args.ContentType)
	args.ResponseWriter.Header().Set("X-Robots-Tag", "noindex")
	args.ResponseWriter.WriteHeader(args.ResponseCode)
	args.ResponseWriter.Write([]byte(a.ReplaceRuntimeVariables(args.Body, args.Request)))
	if a.Verbose {
		fmt.Fprintf(os.Stdout, "[honeypot🟢] serving %s:'%s%s' to %s UA: '%s'\n", args.Request.Method, args.Request.Host, args.Request.RequestURI, a.GetRemoteAddr(args.Request), args.Request.UserAgent())
		_, err := LogBody(args.Request)
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

func PoweredByPHP(rw http.ResponseWriter) {
	rw.Header().Set("X-Powered-By", "PHP/5.3.29")
}

func (a *HoneypotMiddleware) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	SendResponseArgs := CreateSendResponseArgs()
	SendResponseArgs.ResponseWriter = rw
	SendResponseArgs.Request = req
	if IsMatch(req, a.PhpInfoPatterns) {
		PoweredByPHP(rw)
		rw.Header().Set("Server", "Apache/2.4.10 (Debian)")
		SendResponseArgs.Body = phpinfo__html
		a.SendResponse(SendResponseArgs)
		return
	}
	if IsMatch(req, a.XmlRpcPatterns) {
		PoweredByPHP(rw)
		rw.Header().Set("Date", time.Now().Format(http.TimeFormat))
		if req.Method == "GET" {
			rw.Header().Set("Allow", "POST")
			SendResponseArgs.Body = xmlrpc_get
			SendResponseArgs.ContentType = plaintextContentType
			SendResponseArgs.ResponseCode = 405
			a.SendResponse(SendResponseArgs)
			return
		}
		body, err := LogBody(req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[honeypot🔴] Failed to read request body: %s\n", err)
		}
		SendResponseArgs.ContentType = xmlContentType
		rw.Header().Set("Connection", "close")
		rw.Header().Set("Vary", "Accept-Encoding")
		if strings.Count(body, "admin") >= 2 {
			SendResponseArgs.Body = xmlrpc_post_incorrect
			a.SendResponse(SendResponseArgs)
			return
		}
		if strings.Contains(body, "wp.getUsersBlogs") {
			SendResponseArgs.Body = xmlrpc_post_getUserBlogs
			a.SendResponse(SendResponseArgs)
			return
		}
		if strings.Contains(body, "metaWeblog.newPost") {
			SendResponseArgs.Body = xmlrpc_post_newPost
			a.SendResponse(SendResponseArgs)
			return
		}
		SendResponseArgs.Body = xmlrpc_post_notWellFormed
		a.SendResponse(SendResponseArgs)
		return
	}
	if IsMatch(req, a.ExecutionPatterns) {
		a.SendResponse(SendResponseArgs)
		return
	}
	if IsMatch(req, a.DotEnvPatterns) {
		SendResponseArgs.Body = dot__env
		SendResponseArgs.ContentType = plaintextContentType
		a.SendResponse(SendResponseArgs)
		return
	}
	if IsMatch(req, a.WlwmanifestPatterns) {
		SendResponseArgs.Body = wlwmanifest__xml
		SendResponseArgs.ContentType = xmlContentType
		a.SendResponse(SendResponseArgs)
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
	XmlRpcPatterns, err := MakeRegexSlice(config.XmlRpcPatterns)
	if err != nil {
		return nil, err
	}
	return &HoneypotMiddleware{
		next:                next,
		Verbose:             config.Verbose,
		TrustProxy:          config.TrustProxy,
		TrustCF:             config.TrustCF,
		PhpInfoPatterns:     phpInfoPatterns,
		ExecutionPatterns:   executionPatterns,
		XmlRpcPatterns:      XmlRpcPatterns,
		DotEnvPatterns:      dotEnvPatterns,
		WlwmanifestPatterns: wlwmanifestPatterns,
	}, nil
}
