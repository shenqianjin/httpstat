package main

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/bmizerany/perks/quantile"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
)

const (
	httpsTemplate = `` +
		`| DNS Lookup | TCP Connection | TLS Handshake | Request Transfer X Server Processing | Content Transfer|` + "\n" +
		`[ %s  | %s      | %s     | %s        | %s         | %s       ]` + "\n" +
		`             |                |               |                  |                   |                 |` + "\n" +
		`   namelookup:%s       |               |                  |                   |                 |` + "\n" +
		`                       connect:%s      |                  |                   |                 |` + "\n" +
		`                                           tls:%s         |                   |                 |` + "\n" +
		`                                                     reqtransferH:%s          |                 |` + "\n" +
		`                                                      reqtransfer:%s          |                 |` + "\n" +
		`                                                                        starttransfer:%s        |` + "\n" +
		`                                                                                                  total:%s` + "\n"

	httpTemplate = `` +
		`|  DNS Lookup | TCP Connection | Request Transfer X Server Processing | Content Transfer|` + "\n" +
		`[%s    | %s      | %s         | %s        | %s       ]` + "\n" +
		`              |                |                   |                  |                 |` + "\n" +
		`    namelookup:%s       |                   |                  |                 |` + "\n" +
		`                        connect:%s          |                  |                 |` + "\n" +
		`                                        reqtransfer:%s         |                 |` + "\n" +
		`                                                          starttransfer:%s       |` + "\n" +
		`                                                                                   total:%s` + "\n"
)

var (
	// Command line flags.
	httpMethod      string
	postBody        string
	followRedirects bool
	onlyHeader      bool
	insecure        bool
	httpHeaders     headers
	saveOutput      bool
	outputFile      string
	showVersion     bool
	clientCertFile  string
	fourOnly        bool
	sixOnly         bool

	count uint

	// number of redirects followed
	redirectsFollowed int

	version = "devel" // for -v flag, updated during the release process with -ldflags=-X=main.version=...
)

const maxRedirects = 10

func init() {
	flag.StringVar(&httpMethod, "X", "GET", "HTTP method to use")
	flag.StringVar(&postBody, "d", "", "the body of a POST or PUT request; from file use @filename")
	flag.BoolVar(&followRedirects, "L", false, "follow 30x redirects")
	flag.BoolVar(&onlyHeader, "I", false, "don't read body of request")
	flag.BoolVar(&insecure, "k", false, "allow insecure SSL connections")
	flag.Var(&httpHeaders, "H", "set HTTP header; repeatable: -H 'Accept: ...' -H 'Range: ...'")
	flag.BoolVar(&saveOutput, "O", false, "save body as remote filename")
	flag.StringVar(&outputFile, "o", "", "output file for body")
	flag.BoolVar(&showVersion, "v", false, "print version number")
	flag.StringVar(&clientCertFile, "E", "", "client cert file for tls config")
	flag.BoolVar(&fourOnly, "4", false, "resolve IPv4 addresses only")
	flag.BoolVar(&sixOnly, "6", false, "resolve IPv6 addresses only")

	flag.UintVar(&count, "c", 1, "execute repeat count")

	flag.Usage = usage
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS] URL\n\n", os.Args[0])
	fmt.Fprintln(os.Stderr, "OPTIONS:")
	flag.PrintDefaults()
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "ENVIRONMENT:")
	fmt.Fprintln(os.Stderr, "  HTTP_PROXY    proxy for HTTP requests; complete URL or HOST[:PORT]")
	fmt.Fprintln(os.Stderr, "                used for HTTPS requests if HTTPS_PROXY undefined")
	fmt.Fprintln(os.Stderr, "  HTTPS_PROXY   proxy for HTTPS requests; complete URL or HOST[:PORT]")
	fmt.Fprintln(os.Stderr, "  NO_PROXY      comma-separated list of hosts to exclude from proxy")
}

func printf(format string, a ...interface{}) (n int, err error) {
	return fmt.Fprintf(color.Output, format, a...)
}

func grayscale(code color.Attribute) func(string, ...interface{}) string {
	return color.New(code + 232).SprintfFunc()
}

var successCounter atomic.Int32
var requestCounter atomic.Int32

func main() {
	flag.Parse()

	if showVersion {
		fmt.Printf("%s %s (runtime: %s)\n", os.Args[0], version, runtime.Version())
		os.Exit(0)
	}

	if fourOnly && sixOnly {
		fmt.Fprintf(os.Stderr, "%s: Only one of -4 and -6 may be specified\n", os.Args[0])
		os.Exit(-1)
	}

	args := flag.Args()
	if len(args) != 1 {
		flag.Usage()
		os.Exit(2)
	}

	if (httpMethod == "POST" || httpMethod == "PUT") && postBody == "" {
		log.Fatal("must supply post body using -d when POST or PUT is used")
	}

	if onlyHeader {
		httpMethod = "HEAD"
	}

	url := parseURL(args[0])

	statCh := make(chan *httpStat, 1000)
	closeCh := make(chan struct{})
	ctx, cancelFunc := context.WithCancel(context.Background())
	go printStatsTask(ctx, statCh, closeCh)
	for c := 0; c < int(count); c++ {
		requestCounter.Add(1)
		stat, err := visit(url)
		if err != nil {
			log.Printf("ERROR: failed to visit %s: %v", url, err)
			continue
		}
		successCounter.Add(1)
		statCh <- &stat
	}

	cancelFunc()
	<-closeCh
}

func printStatsTask(ctx context.Context, statCh <-chan *httpStat, closeCh chan struct{}) {
	// Print stats of publish rate and latencies
	tick := time.NewTicker(3 * time.Second)
	defer tick.Stop()
	dnsLookupQ := quantile.NewTargeted(0, 0.50, 0.95, 0.99, 0.999, 1.0)
	tcpConnectQ := quantile.NewTargeted(0, 0.50, 0.95, 0.99, 0.999, 1.0)
	tlsHandshakeQ := quantile.NewTargeted(0, 0.50, 0.95, 0.99, 0.999, 1.0)
	reqTransferQ := quantile.NewTargeted(0, 0.50, 0.95, 0.99, 0.999, 1.0)
	reqTransferHQ := quantile.NewTargeted(0, 0.50, 0.95, 0.99, 0.999, 1.0)
	svrProcessingQ := quantile.NewTargeted(0, 0.50, 0.95, 0.99, 0.999, 1.0)
	respTransferQ := quantile.NewTargeted(0, 0.50, 0.95, 0.99, 0.999, 1.0)

	curlRespTransferredQ := quantile.NewTargeted(0, 0.50, 0.95, 0.99, 0.999, 1.0)

	totalStat := httpStat{}

	counter := 0
	for {
		select {
		case <-ctx.Done():
			printStat(printStatOption{
				dnsLookupQ:           dnsLookupQ,
				tcpConnectQ:          tcpConnectQ,
				tlsHandshakeQ:        tlsHandshakeQ,
				reqTransferHQ:        reqTransferHQ,
				reqTransferQ:         reqTransferQ,
				svrProcessingQ:       svrProcessingQ,
				respTransferQ:        respTransferQ,
				curlRespTransferredQ: curlRespTransferredQ,
				counter:              counter,
				totalStat:            &totalStat,
			})
			closeCh <- struct{}{}
			return
		case <-tick.C:
			printStat(printStatOption{
				dnsLookupQ:           dnsLookupQ,
				tcpConnectQ:          tcpConnectQ,
				tlsHandshakeQ:        tlsHandshakeQ,
				reqTransferHQ:        reqTransferHQ,
				reqTransferQ:         reqTransferQ,
				svrProcessingQ:       svrProcessingQ,
				respTransferQ:        respTransferQ,
				curlRespTransferredQ: curlRespTransferredQ,
				counter:              counter,
				totalStat:            &totalStat,
			})
			//dnsLookupQ.Reset()
		case stat := <-statCh:
			dnsLookupQ.Insert(float64(stat.dnsLookup / time.Millisecond))
			tcpConnectQ.Insert(float64(stat.tcpConnect / time.Millisecond))
			tlsHandshakeQ.Insert(float64(stat.tlsHandshake / time.Millisecond))
			reqTransferHQ.Insert(float64(stat.reqTransferH / time.Millisecond))
			reqTransferQ.Insert(float64(stat.reqTransfer / time.Millisecond))
			svrProcessingQ.Insert(float64(stat.svrProcessing / time.Millisecond))
			respTransferQ.Insert(float64(stat.respTransfer / time.Millisecond))
			curlRespTransferredQ.Insert(float64(stat.curlRespTransferred / time.Millisecond))

			totalStat.dnsLookup += stat.dnsLookup
			totalStat.tcpConnect += stat.tcpConnect
			totalStat.tlsHandshake += stat.tlsHandshake
			totalStat.reqTransferH += stat.reqTransferH
			totalStat.reqTransfer += stat.reqTransfer
			totalStat.svrProcessing += stat.svrProcessing
			totalStat.respTransfer += stat.respTransfer

			totalStat.curlConnected += stat.curlConnected
			totalStat.curlTLSHandShook += stat.curlTLSHandShook
			totalStat.curlGotConn += stat.curlGotConn
			totalStat.curlWroteHeaders += stat.curlWroteHeaders
			totalStat.curlReqTransferred += stat.curlReqTransferred
			totalStat.curlGotFirstResponseByte += stat.curlGotFirstResponseByte
			totalStat.curlRespTransferred += stat.curlRespTransferred

			counter++
		}
	}
}

type printStatOption struct {
	dnsLookupQ           *quantile.Stream
	tcpConnectQ          *quantile.Stream
	tlsHandshakeQ        *quantile.Stream
	reqTransferHQ        *quantile.Stream
	reqTransferQ         *quantile.Stream
	svrProcessingQ       *quantile.Stream
	respTransferQ        *quantile.Stream
	curlRespTransferredQ *quantile.Stream

	totalStat *httpStat
	counter   int
}

func printStat(opt printStatOption) {
	if opt.counter <= 0 {
		fmt.Println("all requests were not success")
		return
	}
	fmta := func(d time.Duration) string {
		return color.CyanString("%7dms", int(d/time.Millisecond))
	}

	fmtb := func(d time.Duration) string {
		return color.CyanString("%-9s", strconv.Itoa(int(d/time.Millisecond))+"ms")
	}

	counterD := time.Duration(opt.counter)
	fmtSTA := func(total time.Duration, counter int, q *quantile.Stream) string {
		cD := time.Duration(counter)
		seGs := make([]string, 0)
		seGs = append(seGs, fmt.Sprintf("%-12s", fmt.Sprintf("AVG=%dms", total/cD/time.Millisecond)))
		seGs = append(seGs, fmt.Sprintf("%-12s", fmt.Sprintf("MIN=%.0fms", q.Query(0))))
		seGs = append(seGs, fmt.Sprintf("%-12s", fmt.Sprintf("P50=%.0fms", q.Query(0.5))))
		seGs = append(seGs, fmt.Sprintf("%-12s", fmt.Sprintf("P95=%.0fms", q.Query(0.95))))
		seGs = append(seGs, fmt.Sprintf("%-12s", fmt.Sprintf("P99=%.0fms", q.Query(0.99))))
		seGs = append(seGs, fmt.Sprintf("%-12s", fmt.Sprintf("MAX=%.0fms", q.Query(1))))
		return strings.Join(seGs, "| ")
	}

	colorize := func(s string) string {
		v := strings.Split(s, "\n")
		v[0] = grayscale(16)(v[0])
		return strings.Join(v, "\n")
	}
	totalStat := opt.totalStat
	dnsLookupQ := opt.dnsLookupQ
	tcpConnectQ := opt.tcpConnectQ
	tlsHandshakeQ := opt.tlsHandshakeQ
	reqTransferHQ := opt.reqTransferHQ
	reqTransferQ := opt.reqTransferQ
	svrProcessingQ := opt.svrProcessingQ
	respTransferQ := opt.respTransferQ
	curlRespTransferredQ := opt.curlRespTransferredQ

	fmt.Println("--------------------------------------------------------------------------------------")
	fmt.Printf("DNS Lookup    : %s\n", fmtSTA(opt.totalStat.dnsLookup, opt.counter, dnsLookupQ))
	fmt.Printf("TCP Connect   : %s\n", fmtSTA(opt.totalStat.tcpConnect, opt.counter, tcpConnectQ))
	fmt.Printf("TLS Handshake : %s\n", fmtSTA(opt.totalStat.tlsHandshake, opt.counter, tlsHandshakeQ))
	fmt.Printf("Req TransferH : %s\n", fmtSTA(opt.totalStat.reqTransferH, opt.counter, reqTransferHQ))
	fmt.Printf("Req Transfer  : %s\n", fmtSTA(opt.totalStat.reqTransfer, opt.counter, reqTransferQ))
	fmt.Printf("SVR Processing: %s\n", fmtSTA(opt.totalStat.svrProcessing, opt.counter, svrProcessingQ))
	fmt.Printf("Resp Transfer : %s\n", fmtSTA(opt.totalStat.respTransfer, opt.counter, respTransferQ))
	fmt.Println("--------------------------------------------------------------------------------------")
	fmt.Printf("CURLResponseLA: %s\n", fmtSTA(opt.totalStat.curlRespTransferred, opt.counter, curlRespTransferredQ))
	fmt.Println("--------------------------------------------------------------------------------------")
	fmt.Printf("CURLSuccessRate: %.2f (%d/%d)\n", float32(successCounter.Load())/float32(requestCounter.Load()), successCounter.Load(), requestCounter.Load())
	fmt.Println("--------------------------------------------------------------------------------------")

	printf(colorize(httpsTemplate),
		fmta(totalStat.dnsLookup/counterD),                // dns lookup
		fmta(totalStat.tcpConnect/counterD),               // tcp connection
		fmta(totalStat.tlsHandshake/counterD),             // tls handshake
		fmta(totalStat.reqTransfer/counterD),              // request transfer (add)
		fmta(totalStat.svrProcessing/counterD),            // server processing
		fmta(totalStat.respTransfer/counterD),             // content transfer
		fmtb(totalStat.dnsLookup/counterD),                // namelookup
		fmtb(totalStat.curlConnected/counterD),            // connect
		fmtb(totalStat.curlTLSHandShook/counterD),         // tls (rename)
		fmtb(totalStat.curlWroteHeaders/counterD),         // pretransferHeaders (add)
		fmtb(totalStat.curlReqTransferred/counterD),       // pretransfer --> request transfer (add)
		fmtb(totalStat.curlGotFirstResponseByte/counterD), // starttransfer
		fmtb(totalStat.curlRespTransferred/counterD),      // total
	)
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
