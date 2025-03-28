// nolint: exhaustruct // intentionally vacant fields
package grpcproxy

// This code is borrowed with love from https://github.com/wzshiming/httpproxy
// and lightly refactored to bring necessary code into a single file and do
// a little cleanup.

// MIT License
//
// Copyright (c) 2018-NOW wzshiming
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

const (
	proxyAuthorizationKey = "Proxy-Authorization"
	basicAuthName         = "Basic"
)

// newDialer is create a new HTTP CONNECT connection
func newDialer(addr string) (*dialer, error) {
	d := &dialer{
		Timeout: time.Minute,
	}
	proxy, err := url.Parse(addr)
	if err != nil {
		return nil, err
	}
	d.Userinfo = proxy.User
	switch proxy.Scheme {
	default:
		return nil, fmt.Errorf("unsupported protocol %q", proxy.Scheme)
	case "https":
		hostname := proxy.Hostname()
		host := proxy.Host
		port := proxy.Port()
		if port == "" {
			port = "443"
			host = net.JoinHostPort(hostname, port)
		}
		d.Proxy = host
		d.TLSClientConfig = &tls.Config{
			ServerName: hostname,
		}
	case "http":
		host := proxy.Host
		port := proxy.Port()
		if port == "" {
			port = "80"
			host = net.JoinHostPort(proxy.Hostname(), port)
		}
		d.Proxy = host
	}
	return d, nil
}

// Dialer holds HTTP CONNECT options.
type dialer struct {
	// ProxyDial specifies the optional dial function for
	// establishing the transport connection.
	ProxyDial func(context.Context, string, string) (net.Conn, error)

	// TLSClientConfig specifies the TLS configuration to use with
	// tls.Client.
	// If nil, the TLS is not used.
	// If non-nil, HTTP/2 support may not be enabled by default.
	TLSClientConfig *tls.Config

	// ProxyHeader optionally specifies headers to send to
	// proxies during CONNECT requests.
	ProxyHeader http.Header

	// Proxy proxy server address
	Proxy string

	// Userinfo use userinfo authentication if not empty
	Userinfo *url.Userinfo

	// Timeout is the maximum amount of time a dial will wait for
	// a connect to complete. The default is no timeout
	Timeout time.Duration
}

func (d *dialer) proxyDial(ctx context.Context, network string, address string) (net.Conn, error) {
	proxyDial := d.ProxyDial
	if proxyDial == nil {
		var dialer net.Dialer
		proxyDial = dialer.DialContext
	}

	rawConn, err := proxyDial(ctx, network, address)
	if err != nil {
		return nil, err
	}

	config := d.TLSClientConfig
	if config == nil {
		return rawConn, nil
	}

	conn := tls.Client(rawConn, config)
	err = conn.Handshake()
	if err != nil {
		rawConn.Close()
		return nil, err
	}
	return conn, nil
}

// DialContext connects to the provided address on the provided network.
func (d *dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := d.proxyDial(ctx, network, d.Proxy)
	if err != nil {
		return nil, err
	}

	hdr := d.ProxyHeader
	if hdr == nil {
		hdr = http.Header{}
	}
	if d.Userinfo != nil {
		hdr = hdr.Clone()
		hdr.Set(proxyAuthorizationKey, basicAuth(d.Userinfo))
	}
	connectReq := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: address},
		Host:   address,
		Header: hdr,
	}

	// If there's no done channel (no deadline or cancellation
	// from the caller possible), at least set some (long)
	// timeout here. This will make sure we don't block forever
	// and leak a goroutine if the connection stops replying
	// after the TCP connect.
	connectCtx := ctx
	if d.Timeout != 0 && ctx.Done() == nil {
		newCtx, cancel := context.WithTimeout(ctx, d.Timeout)
		defer cancel()
		connectCtx = newCtx
	}

	didReadResponse := make(chan struct{}) // closed after CONNECT write+read is done or fails
	var (
		resp *http.Response
	)
	// Write the CONNECT request & read the response.
	go func() {
		defer close(didReadResponse)
		err = connectReq.Write(conn)
		if err != nil {
			return
		}
		// Okay to use and discard buffered reader here, because
		// TLS server will not speak until spoken to.
		br := bufio.NewReader(conn)
		resp, err = http.ReadResponse(br, connectReq) //nolint: bodyclose // closing the body hangs; since we're handing off the conn, it is ok.
	}()
	select {
	case <-connectCtx.Done():
		conn.Close()
		<-didReadResponse
		return nil, connectCtx.Err()
	case <-didReadResponse:
		// resp or err now set
	}
	if err != nil {
		conn.Close()
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("failed proxying %d: %q", resp.StatusCode, resp.Status)
	}
	return conn, nil
}

// basicAuth HTTP Basic Authentication string.
func basicAuth(u *url.Userinfo) (base string) {
	s := u.String()
	return basicAuthName + " " + base64.StdEncoding.EncodeToString([]byte(s))
}
