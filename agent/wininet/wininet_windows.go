//go:build windows && amd64

// Package wininet provides HTTP transport via WinINet Windows API.
// Reference: Sliver's drivers/win/wininet — uses system HTTP stack for
// stealth (IE proxy, system SSL certs, legitimate wininet.dll imports).
package wininet

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	// WinINet access types
	InternetOpenTypePreconfig   = 0 // use registry proxy settings
	InternetOpenTypeDirect      = 1 // no proxy
	InternetOpenTypeProxy       = 3 // use specified proxy

	// Services
	InternetServiceHTTP = 3

	// HttpOpenRequest flags
	InternetFlagSecure          = 0x00800000
	InternetFlagReload          = 0x80000000
	InternetFlagKeepConnection  = 0x00000040
	InternetFlagNoCacheWrite    = 0x00040000
	InternetFlagResynchronize   = 0x00000080
	InternetFlagNoUI            = 0x00000200

	// HttpAddRequestHeaders flags
	HTTPAddRequestHeadersAdd    = 0x20000000
	HTTPAddRequestHeadersReplace = 0x80000000

	// InternetOption flags
	InternetOptionConnectTimeout    = 74
	InternetOptionReceiveTimeout    = 75
	InternetOptionSendTimeout       = 76
	InternetOptionSecurityFlags     = 31
	InternetOptionCookie            = 81
	InternetOptionErrorFlags        = 90
	InternetOptionDataReceiveResume = 45

	// Security flags
	SecuritySetMask = 0x0000A000 // ignore cert errors

	// HTTP query info levels
	HTTPQueryStatusCode       = 19
	HTTPQueryStatusText       = 20
	HTTPQueryRawHeadersCRLF   = 22
	HTTPQueryContentLength    = 5
	HTTPQueryContentType      = 1
	HTTPQuerySetCookie        = 43
	HTTPQueryRawHeaders       = 21 | (4 << 16)

	// Error codes
	internetErrorBase              = 12000
	ERROR_INTERNET_INCORRECT_PASSWORD = internetErrorBase + 14
	ERROR_INTERNET_FORCE_RETRY        = internetErrorBase + 32
)

var wininetDLL = windows.NewLazySystemDLL("wininet.dll")

// --- WinINet syscall wrappers ---

func internetOpenW(userAgent string, accessType uintptr, proxy, proxyBypass string, flags uintptr) (uintptr, error) {
	proc := wininetDLL.NewProc("InternetOpenW")
	agentPtr, _ := windows.UTF16PtrFromString(userAgent)
	var proxyPtr, bypassPtr *uint16
	if proxy != "" {
		proxyPtr, _ = windows.UTF16PtrFromString(proxy)
	}
	if proxyBypass != "" {
		bypassPtr, _ = windows.UTF16PtrFromString(proxyBypass)
	}
	ret, _, lastErr := proc.Call(
		uintptr(unsafe.Pointer(agentPtr)),
		accessType,
		uintptr(unsafe.Pointer(proxyPtr)),
		uintptr(unsafe.Pointer(bypassPtr)),
		flags,
	)
	if ret == 0 {
		return 0, fmt.Errorf("InternetOpenW: %w", lastErr)
	}
	return ret, nil
}

func internetConnectW(session uintptr, server string, port int, username, password string, service, flags, context uintptr) (uintptr, error) {
	proc := wininetDLL.NewProc("InternetConnectW")
	serverPtr, _ := windows.UTF16PtrFromString(server)
	var userPtr, passPtr *uint16
	if username != "" {
		userPtr, _ = windows.UTF16PtrFromString(username)
	}
	if password != "" {
		passPtr, _ = windows.UTF16PtrFromString(password)
	}
	ret, _, lastErr := proc.Call(
		session,
		uintptr(unsafe.Pointer(serverPtr)),
		uintptr(port),
		uintptr(unsafe.Pointer(userPtr)),
		uintptr(unsafe.Pointer(passPtr)),
		service,
		flags,
		context,
	)
	if ret == 0 {
		return 0, fmt.Errorf("InternetConnectW: %w", lastErr)
	}
	return ret, nil
}

func httpOpenRequestW(conn uintptr, verb, objectName, version, referrer string, acceptTypes []string, flags, context uintptr) (uintptr, error) {
	proc := wininetDLL.NewProc("HttpOpenRequestW")
	verbPtr, _ := windows.UTF16PtrFromString(verb)
	objPtr, _ := windows.UTF16PtrFromString(objectName)
	verPtr, _ := windows.UTF16PtrFromString(version)
	refPtr, _ := windows.UTF16PtrFromString(referrer)

	acceptPtrs := make([]uintptr, len(acceptTypes)+1)
	for i, t := range acceptTypes {
		p, _ := windows.UTF16PtrFromString(t)
		acceptPtrs[i] = uintptr(unsafe.Pointer(p))
	}
	acceptPtrs[len(acceptPtrs)-1] = 0 // NULL terminator

	ret, _, lastErr := proc.Call(
		conn,
		uintptr(unsafe.Pointer(verbPtr)),
		uintptr(unsafe.Pointer(objPtr)),
		uintptr(unsafe.Pointer(verPtr)),
		uintptr(unsafe.Pointer(refPtr)),
		uintptr(unsafe.Pointer(&acceptPtrs[0])),
		flags,
		context,
	)
	if ret == 0 {
		return 0, fmt.Errorf("HttpOpenRequestW: %w", lastErr)
	}
	return ret, nil
}

func httpSendRequestW(req uintptr, headers string, headersLen int, data []byte, dataLen int) error {
	proc := wininetDLL.NewProc("HttpSendRequestW")
	var hdrPtr *uint16
	var hdrLen uintptr
	if headers != "" {
		hdrPtr, _ = windows.UTF16PtrFromString(headers)
		hdrLen = uintptr(headersLen)
	}
	var dataPtr uintptr
	if len(data) > 0 {
		dataPtr = uintptr(unsafe.Pointer(&data[0]))
	}
	ret, _, lastErr := proc.Call(
		req,
		uintptr(unsafe.Pointer(hdrPtr)),
		hdrLen,
		dataPtr,
		uintptr(dataLen),
	)
	if ret == 0 {
		return fmt.Errorf("HttpSendRequestW: %w", lastErr)
	}
	return nil
}

func httpQueryInfoW(req uintptr, info uintptr, buffer []byte, bufferLen *int, index *int) error {
	proc := wininetDLL.NewProc("HttpQueryInfoW")
	ret, _, lastErr := proc.Call(
		req,
		info,
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(unsafe.Pointer(bufferLen)),
		uintptr(unsafe.Pointer(index)),
	)
	if ret == 0 {
		return fmt.Errorf("HttpQueryInfoW: %w", lastErr)
	}
	return nil
}

func internetReadFile(req uintptr, buffer []byte, bytesToRead int64, bytesRead *int64) error {
	proc := wininetDLL.NewProc("InternetReadFile")
	ret, _, lastErr := proc.Call(
		req,
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(bytesToRead),
		uintptr(unsafe.Pointer(bytesRead)),
	)
	if ret == 0 {
		return fmt.Errorf("InternetReadFile: %w", lastErr)
	}
	return nil
}

func internetQueryDataAvailable(req uintptr, bytesAvailable *int64) error {
	proc := wininetDLL.NewProc("InternetQueryDataAvailable")
	ret, _, lastErr := proc.Call(
		req,
		uintptr(unsafe.Pointer(bytesAvailable)),
		0, 0,
	)
	if ret == 0 {
		return fmt.Errorf("InternetQueryDataAvailable: %w", lastErr)
	}
	return nil
}

func internetSetOptionW(h uintptr, opt uintptr, val []byte, valLen int) error {
	proc := wininetDLL.NewProc("InternetSetOptionW")
	if valLen == 0 {
		val = []byte{0}
	}
	ret, _, lastErr := proc.Call(
		h,
		opt,
		uintptr(unsafe.Pointer(&val[0])),
		uintptr(valLen),
	)
	if ret == 0 {
		return fmt.Errorf("InternetSetOptionW: %w", lastErr)
	}
	return nil
}

func internetCloseHandle(h uintptr) error {
	proc := wininetDLL.NewProc("InternetCloseHandle")
	ret, _, lastErr := proc.Call(h)
	if ret == 0 {
		return fmt.Errorf("InternetCloseHandle: %w", lastErr)
	}
	return nil
}

// --- Client ---

// Client wraps WinINet to implement http.RoundTripper.
type Client struct {
	session  uintptr
	userAgent string
	Timeout  time.Duration
	TLSConfig *tls.Config
	CookieJar *cookieJar
}

// NewClient creates a new WinINet HTTP client.
func NewClient(userAgent string) (*Client, error) {
	session, err := internetOpenW(userAgent, InternetOpenTypePreconfig, "", "", 0)
	if err != nil {
		return nil, fmt.Errorf("create WinINet session: %w", err)
	}
	return &Client{
		session:   session,
		userAgent: userAgent,
		CookieJar: newCookieJar(),
	}, nil
}

// RoundTrip implements http.RoundTripper using WinINet API.
func (c *Client) RoundTrip(req *http.Request) (*http.Response, error) {
	u, err := url.Parse(req.URL.String())
	if err != nil {
		return nil, fmt.Errorf("parse URL: %w", err)
	}

	port := 80
	secure := false
	if u.Scheme == "https" {
		secure = true
		port = 443
	}
	if u.Port() != "" {
		fmt.Sscanf(u.Port(), "%d", &port)
	}

	// Connect to server
	conn, err := internetConnectW(c.session, u.Hostname(), port, "", "", InternetServiceHTTP, 0, 0)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	defer internetCloseHandle(conn)

	// Build request
	verb := req.Method
	object := u.Path
	if u.RawQuery != "" {
		object += "?" + u.RawQuery
	}

	flags := InternetFlagNoCacheWrite | InternetFlagKeepConnection
	if secure {
		flags |= InternetFlagSecure
	}

	hReq, err := httpOpenRequestW(conn, verb, object, "HTTP/1.1", "", []string{"*/*"}, uintptr(flags), 0)
	if err != nil {
		return nil, fmt.Errorf("open request: %w", err)
	}
	defer internetCloseHandle(hReq)

	// Set timeouts
	if c.Timeout > 0 {
		timeoutBuf := make([]byte, 4)
		*(*uint32)(unsafe.Pointer(&timeoutBuf[0])) = uint32(c.Timeout.Milliseconds())
		for _, opt := range []uintptr{InternetOptionConnectTimeout, InternetOptionReceiveTimeout, InternetOptionSendTimeout} {
			internetSetOptionW(hReq, opt, timeoutBuf, len(timeoutBuf))
		}
	}

	// Disable cert verification if configured
	if c.TLSConfig != nil && c.TLSConfig.InsecureSkipVerify {
		secBuf := make([]byte, 4)
		*(*uint32)(unsafe.Pointer(&secBuf[0])) = SecuritySetMask
		internetSetOptionW(hReq, InternetOptionSecurityFlags, secBuf, len(secBuf))
	}

	// Add custom headers
	for k, vv := range req.Header {
		for _, v := range vv {
			hdr := fmt.Sprintf("%s: %s\r\n", k, v)
			httpAddRequestHeadersW(hReq, hdr, HTTPAddRequestHeadersAdd|HTTPAddRequestHeadersReplace)
		}
	}

	// Add cookies from jar
	if c.CookieJar != nil {
		for _, ck := range c.CookieJar.cookiesForURL(u) {
			hdr := fmt.Sprintf("Cookie: %s=%s\r\n", ck.name, ck.value)
			httpAddRequestHeadersW(hReq, hdr, HTTPAddRequestHeadersAdd)
		}
	}

	// Read body
	var body []byte
	if req.Body != nil {
		body, _ = io.ReadAll(req.Body)
		req.Body.Close()
	}

	// Send request
	var hdrStr string
	// Read existing headers
	var hdrBuf = make([]byte, 4096)
	hdrLen := len(hdrBuf)
	if httpQueryInfoW(hReq, HTTPQueryRawHeaders, hdrBuf, &hdrLen, nil) == nil {
		hdrStr = string(hdrBuf[:hdrLen])
	}
	_ = hdrStr // headers already set via httpAddRequestHeadersW

	if err := httpSendRequestW(hReq, "", 0, body, len(body)); err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}

	// Read status code
	statusBuf := make([]byte, 64)
	statusLen := len(statusBuf)
	if err := httpQueryInfoW(hReq, HTTPQueryStatusCode, statusBuf, &statusLen, nil); err != nil {
		return nil, fmt.Errorf("query status: %w", err)
	}
	statusCode := 0
	fmt.Sscanf(string(statusBuf[:statusLen]), "%d", &statusCode)

	// Read status text
	textBuf := make([]byte, 256)
	textLen := len(textBuf)
	httpQueryInfoW(hReq, HTTPQueryStatusText, textBuf, &textLen, nil)
	statusText := string(textBuf[:textLen])
	if statusText == "" {
		statusText = http.StatusText(statusCode)
	}

	// Read response headers
	respHdrBuf := make([]byte, 4096)
	respHdrLen := len(respHdrBuf)
	httpQueryInfoW(hReq, HTTPQueryRawHeadersCRLF, respHdrBuf, &respHdrLen, nil)

	// Parse Set-Cookie headers and store in jar
	ckBuf := make([]byte, 4096)
	ckLen := len(ckBuf)
	idx := 0
	for httpQueryInfoW(hReq, HTTPQuerySetCookie, ckBuf, &ckLen, &idx) == nil {
		// Parse simple name=value cookies
		cookieStr := string(ckBuf[:ckLen])
		for _, part := range strings.Split(cookieStr, ";") {
			part = strings.TrimSpace(part)
			if eq := strings.Index(part, "="); eq > 0 {
				name := strings.TrimSpace(part[:eq])
				value := strings.TrimSpace(part[eq+1:])
				if name != "" && c.CookieJar != nil {
					c.CookieJar.set(u, name, value)
				}
			}
		}
		ckBuf = make([]byte, 4096)
		ckLen = len(ckBuf)
		idx++
	}
	_ = respHdrBuf[:respHdrLen]

	// Read response body
	var bodyBuf bytes.Buffer
	for {
		var avail int64
		if err := internetQueryDataAvailable(hReq, &avail); err != nil {
			break
		}
		if avail <= 0 {
			break
		}
		chunk := make([]byte, avail)
		var read int64
		if err := internetReadFile(hReq, chunk, avail, &read); err != nil {
			break
		}
		if read <= 0 {
			break
		}
		bodyBuf.Write(chunk[:read])
	}

	headers := make(http.Header)
	// Parse raw headers string
	rawHeaders := string(respHdrBuf[:respHdrLen])
	for _, line := range strings.Split(rawHeaders, "\r\n") {
		if colon := strings.Index(line, ":"); colon > 0 {
			k := strings.TrimSpace(line[:colon])
			v := strings.TrimSpace(line[colon+1:])
			if k != "" {
				headers.Add(k, v)
			}
		}
	}

	return &http.Response{
		Status:        fmt.Sprintf("%d %s", statusCode, statusText),
		StatusCode:    statusCode,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        headers,
		Body:          io.NopCloser(&bodyBuf),
		ContentLength: int64(bodyBuf.Len()),
		Request:       req,
	}, nil
}

// Close releases the WinINet session handle.
func (c *Client) Close() {
	if c.session != 0 {
		internetCloseHandle(c.session)
		c.session = 0
	}
}

func httpAddRequestHeadersW(req uintptr, header string, addMethod uintptr) {
	hdrPtr, _ := windows.UTF16PtrFromString(header)
	wininetDLL.NewProc("HttpAddRequestHeadersW").Call(
		req,
		uintptr(unsafe.Pointer(hdrPtr)),
		uintptr(len(header)),
		addMethod,
	)
}

// --- Cookie Jar ---

type cookie struct {
	name  string
	value string
}

type cookieJar struct {
	mu      sync.Mutex
	cookies []cookie
}

func newCookieJar() *cookieJar {
	return &cookieJar{}
}

func (j *cookieJar) set(u *url.URL, name, value string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	for i, c := range j.cookies {
		if c.name == name {
			j.cookies[i].value = value
			return
		}
	}
	j.cookies = append(j.cookies, cookie{name: name, value: value})
}

func (j *cookieJar) cookiesForURL(u *url.URL) []cookie {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.cookies
}
