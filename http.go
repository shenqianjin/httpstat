package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/fatih/color"
	"log"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
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
