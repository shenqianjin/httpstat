package main

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/fatih/color"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"
	"time"
)

// visit visits a url and times the interaction.
// If the response is a 30x, visit follows the redirect.
func visit(url *url.URL) (stat httpStat, err error) {
	req := newRequest(httpMethod, url, postBody)

	var dnsStart, dnsDone, connectDone, gotConn, gotFirstResponseByte, tlsHandshakeStart, tlsHandshakeDone time.Time
	var connectStart, wroteHeaders, wroteRequest time.Time

	trace := &httptrace.ClientTrace{
		DNSStart: func(_ httptrace.DNSStartInfo) {
			dnsStart = time.Now()
			//fmt.Printf(" ------ DNS start: %v\n", dnsStart)
		},
		DNSDone: func(_ httptrace.DNSDoneInfo) {
			dnsDone = time.Now()
			//fmt.Printf(" ------ DNS Done: %v\n", dnsDone)
		},
		ConnectStart: func(_, _ string) {
			now := time.Now()
			if dnsDone.IsZero() {
				// connecting to IP
				dnsDone = now
			}
			connectStart = now
			//fmt.Printf(" ------ ConnectStart: %v\n", connectStart)
		},
		ConnectDone: func(net, addr string, err error) {
			if err != nil {
				log.Fatalf("unable to connect to host %v: %v", addr, err)
			}
			connectDone = time.Now()
			//fmt.Printf(" ------ connectDone: %v\n", connectDone)

			printf("\n%s%s\n", color.GreenString("Connected to "), color.CyanString(addr))
		},
		GotConn: func(_ httptrace.GotConnInfo) {
			gotConn = time.Now()
			//fmt.Printf(" ------ gotConn: %v\n", gotConn)
		},
		WroteHeaders: func() {
			wroteHeaders = time.Now()
		},
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			wroteRequest = time.Now()
			//fmt.Printf(" ------ wroteRequest: %v\n", wroteRequest)
		},
		GotFirstResponseByte: func() {
			gotFirstResponseByte = time.Now()
			//fmt.Printf(" ------ gotFirstResponseByte: %v\n", gotFirstResponseByte)
		},
		TLSHandshakeStart: func() {
			tlsHandshakeStart = time.Now()
			//fmt.Printf(" ------ tlsHandshakeStart: %v\n", tlsHandshakeStart)
		},
		TLSHandshakeDone: func(_ tls.ConnectionState, _ error) {
			tlsHandshakeDone = time.Now()
			//fmt.Printf(" ------ tlsHandshakeDone: %v\n", tlsHandshakeDone)
		},
	}
	req = req.WithContext(httptrace.WithClientTrace(context.Background(), trace))

	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     true,
	}

	switch {
	case fourOnly:
		tr.DialContext = dialContext("tcp4")
	case sixOnly:
		tr.DialContext = dialContext("tcp6")
	}

	switch url.Scheme {
	case "https":
		host, _, err := net.SplitHostPort(req.Host)
		if err != nil {
			host = req.Host
		}

		tr.TLSClientConfig = &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: insecure,
			Certificates:       readClientCert(clientCertFile),
			MinVersion:         tls.VersionTLS12,
		}
	}

	client := &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// always refuse to follow redirects, visit does that
			// manually if required.
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		err = fmt.Errorf("failed to read response: %w", err)
		return
	} else if resp.StatusCode/100 != 2 {
		err = fmt.Errorf("failed to visit [%s], status: %s, body: %s", req.URL.String(), resp.Status, readResponseBody(req, resp))
		return
	}

	// Print SSL/TLS version which is used for connection
	connectedVia := "plaintext"
	if resp.TLS != nil {
		switch resp.TLS.Version {
		case tls.VersionTLS12:
			connectedVia = "TLSv1.2"
		case tls.VersionTLS13:
			connectedVia = "TLSv1.3"
		}
	}
	printf("\n%s %s\n", color.GreenString("Connected via"), color.CyanString("%s", connectedVia))

	bodyMsg := readResponseBody(req, resp)
	resp.Body.Close()

	gotAllRespnseBody := time.Now() // after read body
	if dnsStart.IsZero() {
		// we skipped DNS
		dnsStart = dnsDone
	}

	// print status line and headers
	printf("\n%s%s%s\n", color.GreenString("HTTP"), grayscale(14)("/"), color.CyanString("%d.%d %s", resp.ProtoMajor, resp.ProtoMinor, resp.Status))

	names := make([]string, 0, len(resp.Header))
	for k := range resp.Header {
		names = append(names, k)
	}
	sort.Sort(headers(names))
	for _, k := range names {
		printf("%s %s\n", grayscale(14)(k+":"), color.CyanString(strings.Join(resp.Header[k], ",")))
	}

	if bodyMsg != "" {
		printf("\n%s\n", bodyMsg)
	}

	/*switch url.Scheme {
	case "https":
		printf(colorize(httpsTemplate),
			fmta(dnsDone.Sub(dnsStart)),                       // dns lookup
			fmta(connectDone.Sub(connectStart)),               // tcp connection
			fmta(tlsHandshakeDone.Sub(tlsHandshakeStart)),     // tls handshake
			fmta(wroteRequest.Sub(gotConn)),                   // request transfer (add)
			fmta(gotFirstResponseByte.Sub(wroteRequest)),      // server processing
			fmta(gotAllRespnseBody.Sub(gotFirstResponseByte)), // content transfer
			fmtb(dnsDone.Sub(dnsStart)),                       // namelookup
			fmtb(connectDone.Sub(dnsStart)),                   // connect
			fmtb(tlsHandshakeDone.Sub(dnsStart)),              // tls (rename)
			fmtb(wroteRequest.Sub(dnsStart)),                  // pretransfer --> request transfer (add)
			fmtb(gotFirstResponseByte.Sub(dnsStart)),          // starttransfer
			fmtb(gotAllRespnseBody.Sub(dnsStart)),             // total
		)
	case "http":
		printf(colorize(httpTemplate),
			fmta(dnsDone.Sub(dnsStart)),                       // dns lookup
			fmta(gotConn.Sub(dnsDone)),                        // tcp connection
			fmta(wroteRequest.Sub(gotConn)),                   // request transfer (add)
			fmta(gotFirstResponseByte.Sub(wroteRequest)),      // server processing
			fmta(gotAllRespnseBody.Sub(gotFirstResponseByte)), // content transfer
			fmtb(dnsDone.Sub(dnsStart)),                       // namelookup
			fmtb(gotConn.Sub(dnsStart)),                       // connect
			fmtb(wroteRequest.Sub(dnsStart)),                  // pretransfer --> request transfer (add)
			fmtb(gotFirstResponseByte.Sub(dnsStart)),          // starttransfer
			fmtb(gotAllRespnseBody.Sub(dnsStart)),             // total
		)
	}*/
	stat = httpStat{
		dnsLookup:     dnsDone.Sub(dnsStart),
		tcpConnect:    connectDone.Sub(connectStart),
		tlsHandshake:  tlsHandshakeDone.Sub(tlsHandshakeStart),
		reqTransferH:  wroteHeaders.Sub(gotConn),
		reqTransfer:   wroteRequest.Sub(gotConn),
		svrProcessing: gotFirstResponseByte.Sub(wroteHeaders), // 写完header服务端就可以处理了
		respTransfer:  gotAllRespnseBody.Sub(gotFirstResponseByte),

		curlConnected:            connectDone.Sub(dnsStart),
		curlGotConn:              gotConn.Sub(dnsStart),
		curlWroteHeaders:         wroteHeaders.Sub(dnsStart),
		curlReqTransferred:       wroteRequest.Sub(dnsStart),
		curlGotFirstResponseByte: gotFirstResponseByte.Sub(dnsStart),
		curlRespTransferred:      gotAllRespnseBody.Sub(dnsStart),
	}
	if !tlsHandshakeDone.IsZero() {
		stat.tlsHandshake = tlsHandshakeDone.Sub(tlsHandshakeStart)
		stat.curlTLSHandShook = tlsHandshakeDone.Sub(dnsStart)
	}

	if followRedirects && isRedirect(resp) {
		loc, err1 := resp.Location()
		if err1 != nil {
			if errors.Is(err1, http.ErrNoLocation) {
				// 30x but no Location to follow, give up.
				return
			}
			err = fmt.Errorf("unable to follow redirect: %w", err1)
			return
		}

		redirectsFollowed++
		if redirectsFollowed > maxRedirects {
			err = fmt.Errorf("maximum number of redirects (%d) followed", maxRedirects)
			return
		}

		visit(loc)
	}

	return
}

type httpStat struct {
	// 阶段耗时

	dnsLookup     time.Duration
	tcpConnect    time.Duration
	tlsHandshake  time.Duration
	reqTransferH  time.Duration
	reqTransfer   time.Duration // 包含 reqTransferH
	svrProcessing time.Duration
	respTransfer  time.Duration

	// 累计耗时

	curlConnected            time.Duration
	curlTLSHandShook         time.Duration
	curlGotConn              time.Duration
	curlWroteHeaders         time.Duration
	curlReqTransferred       time.Duration
	curlGotFirstResponseByte time.Duration
	curlRespTransferred      time.Duration
}

// readClientCert - helper function to read client certificate
// from pem formatted file
func readClientCert(filename string) []tls.Certificate {
	if filename == "" {
		return nil
	}
	var (
		pkeyPem []byte
		certPem []byte
	)

	// read client certificate file (must include client private key and certificate)
	certFileBytes, err := os.ReadFile(filename)
	if err != nil {
		log.Fatalf("failed to read client certificate file: %v", err)
	}

	for {
		block, rest := pem.Decode(certFileBytes)
		if block == nil {
			break
		}
		certFileBytes = rest

		if strings.HasSuffix(block.Type, "PRIVATE KEY") {
			pkeyPem = pem.EncodeToMemory(block)
		}
		if strings.HasSuffix(block.Type, "CERTIFICATE") {
			certPem = pem.EncodeToMemory(block)
		}
	}

	cert, err := tls.X509KeyPair(certPem, pkeyPem)
	if err != nil {
		log.Fatalf("unable to load client cert and key pair: %v", err)
	}
	return []tls.Certificate{cert}
}

func parseURL(uri string) *url.URL {
	if !strings.Contains(uri, "://") && !strings.HasPrefix(uri, "//") {
		uri = "//" + uri
	}

	url, err := url.Parse(uri)
	if err != nil {
		log.Fatalf("could not parse url %q: %v", uri, err)
	}

	if url.Scheme == "" {
		url.Scheme = "http"
		if !strings.HasSuffix(url.Host, ":80") {
			url.Scheme += "s"
		}
	}
	return url
}

func headerKeyValue(h string) (string, string) {
	i := strings.Index(h, ":")
	if i == -1 {
		log.Fatalf("Header '%s' has invalid format, missing ':'", h)
	}
	return strings.TrimRight(h[:i], " "), strings.TrimLeft(h[i:], " :")
}

func dialContext(network string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, _, addr string) (net.Conn, error) {
		return (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: false,
		}).DialContext(ctx, network, addr)
	}
}

func isRedirect(resp *http.Response) bool {
	return resp.StatusCode > 299 && resp.StatusCode < 400
}

func newRequest(method string, url *url.URL, body string) *http.Request {
	req, err := http.NewRequest(method, url.String(), createBody(body))
	if err != nil {
		log.Fatalf("unable to create request: %v", err)
	}
	for _, h := range httpHeaders {
		k, v := headerKeyValue(h)
		if strings.EqualFold(k, "host") {
			req.Host = v
			continue
		}
		req.Header.Add(k, v)
	}
	return req
}

func createBody(body string) io.Reader {
	if strings.HasPrefix(body, "@") {
		filename := body[1:]
		f, err := os.Open(filename)
		if err != nil {
			log.Fatalf("failed to open data file %s: %v", filename, err)
		}
		return f
	}
	return strings.NewReader(body)
}

// getFilenameFromHeaders tries to automatically determine the output filename,
// when saving to disk, based on the Content-Disposition header.
// If the header is not present, or it does not contain enough information to
// determine which filename to use, this function returns "".
func getFilenameFromHeaders(headers http.Header) string {
	// if the Content-Disposition header is set parse it
	if hdr := headers.Get("Content-Disposition"); hdr != "" {
		// pull the media type, and subsequent params, from
		// the body of the header field
		mt, params, err := mime.ParseMediaType(hdr)

		// if there was no error and the media type is attachment
		if err == nil && mt == "attachment" {
			if filename := params["filename"]; filename != "" {
				return filename
			}
		}
	}

	// return an empty string if we were unable to determine the filename
	return ""
}

// readResponseBody consumes the body of the response.
// readResponseBody returns an informational message about the
// disposition of the response body's contents.
func readResponseBody(req *http.Request, resp *http.Response) string {
	if isRedirect(resp) || req.Method == http.MethodHead {
		return ""
	}

	w := io.Discard
	msg := color.CyanString("Body discarded")

	if saveOutput || outputFile != "" {
		filename := outputFile

		if saveOutput {
			// try to get the filename from the Content-Disposition header
			// otherwise fall back to the RequestURI
			if filename = getFilenameFromHeaders(resp.Header); filename == "" {
				filename = path.Base(req.URL.RequestURI())
			}

			if filename == "/" {
				log.Fatalf("No remote filename; specify output filename with -o to save response body")
			}
		}

		f, err := os.Create(filename)
		if err != nil {
			log.Fatalf("unable to create file %s: %v", filename, err)
		}
		defer f.Close()
		w = f
		msg = color.CyanString("Body read")
	}

	if _, err := io.Copy(w, resp.Body); err != nil && w != io.Discard {
		log.Fatalf("failed to read response body: %v", err)
	}

	return msg
}

type headers []string

func (h headers) String() string {
	var o []string
	for _, v := range h {
		o = append(o, "-H "+v)
	}
	return strings.Join(o, " ")
}

func (h *headers) Set(v string) error {
	*h = append(*h, v)
	return nil
}

func (h headers) Len() int      { return len(h) }
func (h headers) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h headers) Less(i, j int) bool {
	a, b := h[i], h[j]

	// server always sorts at the top
	if a == "Server" {
		return true
	}
	if b == "Server" {
		return false
	}

	endtoend := func(n string) bool {
		// https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html#sec13.5.1
		switch n {
		case "Connection",
			"Keep-Alive",
			"Proxy-Authenticate",
			"Proxy-Authorization",
			"TE",
			"Trailers",
			"Transfer-Encoding",
			"Upgrade":
			return false
		default:
			return true
		}
	}

	x, y := endtoend(a), endtoend(b)
	if x == y {
		// both are of the same class
		return a < b
	}
	return x
}
