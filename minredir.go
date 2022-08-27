package minredir

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strings"
	"text/template"
	"time"
)

type result struct {
	Color   string
	Icon    string
	Message string
}

type config struct {
	pattern string
	extract func(r *http.Request, resultChan chan string) bool

	pageTempl string
	title     string

	success, failure result
}

func defaultConfig() config {
	return config{
		pattern: "/",
		extract: ExtractOAuth2Code,

		pageTempl: `<html>
	<head><title>{{.Result.Icon}} {{.Title}}</title></head>
    <style>
    .icon { animation: anim .3s linear }
    @keyframes anim { 0% { background-color:green } }
    </style>
	<body onload="open(location, '_self').close(); window.stop()"> <!-- close or stop connecting to a server -->
    	<div>
            <span style="font-size:xx-large; color:{{.Result.Color}}; border:solid thin {{.Result.Color}};" class="icon">{{.Result.Icon}}</span>
            {{.Result.Message}}
        </div>
		<hr />
		<p>This is a temporary page.<br />Please close it.</p>
	</body>
</html>
`,
		title: "Auth",

		success: result{Color: "green", Icon: "&#10003;", Message: "Successfully authenticated!!"},
		failure: result{Color: "red", Icon: "&#10008;", Message: "FAILED!"},
	}
}

type option func(*config)

func Pattern(pattern string) option {
	return func(c *config) {
		c.pattern = pattern
	}
}

func Extract(extract func(r *http.Request, resultChan chan string) bool) option {
	return func(c *config) {
		c.extract = extract
	}
}

func PageTempl(pageTempl string) option {
	return func(c *config) {
		c.pageTempl = pageTempl
	}
}

func Title(title string) option {
	return func(c *config) {
		c.title = title
	}
}

func Success(color, icon, message string) option {
	return func(c *config) {
		c.success = result{
			Color:   color,
			Icon:    icon,
			Message: message,
		}
	}
}

func Failure(color, icon, message string) option {
	return func(c *config) {
		c.failure = result{
			Color:   color,
			Icon:    icon,
			Message: message,
		}
	}
}

// ExtractOAuth2Code exitracts `code` from OAuth2 HTTP response.
func ExtractOAuth2Code(r *http.Request, resultChan chan string) bool {
	code := r.FormValue("code")
	resultChan <- code
	return (code != "")
}

// Serve launches temporal HTTP server.
func Serve(ctx context.Context, addr string, resultChan chan string, opts ...option) (prepErr error, serveErr chan error) {
	config := defaultConfig()
	for _, o := range opts {
		o(&config)
	}

	templ, err := template.New("").Parse(config.pageTempl)
	if err != nil {
		return err, nil
	}

	serveMux := http.ServeMux{}
	server := &http.Server{
		Addr:              addr,
		Handler:           &serveMux,
		ReadHeaderTimeout: 60 * time.Second,
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err, nil
	}

	errChan := make(chan error, 2)

	serveMux.HandleFunc(config.pattern, func(w http.ResponseWriter, r *http.Request) {
		ok := config.extract(r, resultChan)

		data := struct {
			Title  string
			Result result
		}{
			Title: config.title,
		}
		if ok {
			data.Result = config.success
		} else {
			data.Result = config.failure
		}
		err := templ.Execute(w, data)
		if err != nil {
			errChan <- err
		}

		_ = server.Shutdown(ctx)
	})

	go func() {
		err := server.Serve(ln)
		errChan <- err
	}()

	return nil, errChan
}

func ServeTLS(ctx context.Context, addr string, resultChan chan string, opts ...option) (prepErr error, serveErr chan error) {
	config := defaultConfig()
	for _, o := range opts {
		o(&config)
	}

	templ, err := template.New("").Parse(config.pageTempl)
	if err != nil {
		return err, nil
	}

	serveMux := http.ServeMux{}
	server := &http.Server{
		Addr:              addr,
		Handler:           &serveMux,
		ReadHeaderTimeout: 60 * time.Second,
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err, nil
	}

	errChan := make(chan error, 2)

	serveMux.HandleFunc(config.pattern, func(w http.ResponseWriter, r *http.Request) {
		ok := config.extract(r, resultChan)

		data := struct {
			Title  string
			Result result
		}{
			Title: config.title,
		}
		if ok {
			data.Result = config.success
		} else {
			data.Result = config.failure
		}
		err := templ.Execute(w, data)
		if err != nil {
			errChan <- err
		}

		_ = server.Shutdown(ctx)
	})

	tlsconfig := tls.Config{MinVersion: tls.VersionTLS12}
	tlsconfig.NextProtos = []string{"http/1.1"}
	tlsconfig.Certificates = make([]tls.Certificate, 1)
	tlsconfig.Certificates[0], err = generateCert("localhost")
	if err != nil {
		return err, nil
	}

	tlsListener := tls.NewListener(ln, &tlsconfig)

	go func() {
		err := server.Serve(tlsListener)
		errChan <- err
	}()

	return nil, errChan
}

func publicKey(priv any) any {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	case ed25519.PrivateKey:
		return k.Public().(ed25519.PublicKey)
	default:
		return nil
	}
}

// go/src/crypto/tls/generate_cert.go

func generateCert(host string) (tls.Certificate, error) {
	var priv any
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("Failed to generate private key: %w", err)
	}

	keyUsage := x509.KeyUsageDigitalSignature
	if _, isRSA := priv.(*rsa.PrivateKey); isRSA {
		keyUsage |= x509.KeyUsageKeyEncipherment
	}

	notBefore := time.Now()

	notAfter := notBefore.Add(24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("Failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	hosts := strings.Split(host, ",")
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	template.IsCA = true
	template.KeyUsage |= x509.KeyUsageCertSign

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(priv), priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("Failed to create certificate: %w", err)
	}

	cert := &bytes.Buffer{}
	key := &bytes.Buffer{}
	if err := pem.Encode(cert, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return tls.Certificate{}, fmt.Errorf("Failed to write data: %w", err)
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("Unable to marshal private key: %w", err)
	}
	if err := pem.Encode(key, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		return tls.Certificate{}, fmt.Errorf("Failed to write data: %w", err)
	}

	return tls.X509KeyPair(cert.Bytes(), key.Bytes())
}
