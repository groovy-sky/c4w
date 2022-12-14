package main

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/csv"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/ocsp"
)

const ccadbRootCA = `
-----BEGIN CERTIFICATE-----
MIIDrzCCApegAwIBAgIQCDvgVpBCRrGhdWrJWZHHSjANBgkqhkiG9w0BAQUFADBh
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBD
QTAeFw0wNjExMTAwMDAwMDBaFw0zMTExMTAwMDAwMDBaMGExCzAJBgNVBAYTAlVT
MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
b20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IENBMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4jvhEXLeqKTTo1eqUKKPC3eQyaKl7hLOllsB
CSDMAZOnTjC3U/dDxGkAV53ijSLdhwZAAIEJzs4bg7/fzTtxRuLWZscFs3YnFo97
nh6Vfe63SKMI2tavegw5BmV/Sl0fvBf4q77uKNd0f3p4mVmFaG5cIzJLv07A6Fpt
43C/dxC//AH2hdmoRBBYMql1GNXRor5H4idq9Joz+EkIYIvUX7Q6hL+hqkpMfT7P
T19sdl6gSzeRntwi5m3OFBqOasv+zbMUZBfHWymeMr/y7vrTC0LUq7dBMtoM1O/4
gdW7jVg/tRvoSSiicNoxBN33shbyTApOB6jtSj1etX+jkMOvJwIDAQABo2MwYTAO
BgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUA95QNVbR
TLtm8KPiGxvDl7I90VUwHwYDVR0jBBgwFoAUA95QNVbRTLtm8KPiGxvDl7I90VUw
DQYJKoZIhvcNAQEFBQADggEBAMucN6pIExIK+t1EnE9SsPTfrgT1eXkIoyQY/Esr
hMAtudXH/vTBH1jLuG2cenTnmCmrEbXjcKChzUyImZOMkXDiqw8cvpOp/2PV5Adg
06O/nVsJ8dWO41P0jmP6P6fbtGbfYmbW0W5BjfIttep3Sp+dWOIrWcBAI+0tKIJF
PnlUkiaY4IBIqDfv8NZ5YBberOgOzW6sRBc4L0na4UU+Krk2U886UAb3LujEV0ls
YSEY1QSteDwsOoBrp+uvFRTp2InBuThs4pFsiv9kuXclVzDAGySj4dzp30d8tbQk
CAUw7C29C79Fv1C5qfPrmAESrciIxpg0X40KPMbp1ZWVbd4=
-----END CERTIFICATE-----
`

type WebValidator struct {
	Roots  *x509.CertPool
	Client *http.Client
}

func (v *WebValidator) Init(insecure bool) {
	// Initiate empty CA cert pool for validator
	roots := x509.NewCertPool()

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure, RootCAs: roots},
	}
	client := &http.Client{Transport: tr}

	v.Client = client
	v.Roots = roots

}

func (v *WebValidator) CheckCert(c *x509.Certificate) {
	// Checks certificate validity
	tn := time.Now().Unix()
	switch {
	case c.NotBefore.Unix() > tn:
		fmt.Println("Inactive Certificate")
		fallthrough
	case c.NotAfter.Unix() < tn:
		fmt.Println("Expired Certificate")
	default:
		fmt.Println("No problem found")
	}
}

func (v *WebValidator) AddCert(cert []byte) {
	// Appends CA store
	v.Roots.AppendCertsFromPEM(cert)
}

func (v *WebValidator) AddMozillaCA() {
	// Download and add Mozilla's Root CAs
	resp, err := v.Client.Get("https://ccadb-public.secure.force.com/mozilla/IncludedRootsDistrustTLSSSLPEMCSV?TrustBitsInclude=Websites")

	if err != nil {
		log.Fatal("Couldn't download CSV file")
	}
	defer resp.Body.Close()

	r := csv.NewReader(resp.Body)
	// https://stackoverflow.com/questions/31326659/golang-csv-error-bare-in-non-quoted-field
	r.LazyQuotes = true

	for {
		// Read each record from CSV and appends CA store till end of the file
		record, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Println(err)
		} else {
			newCert := record[0][1 : len(record[0])-1]
			v.AddCert([]byte(newCert))

		}

	}
}

func (v *WebValidator) CheckWeb(url string) ([]*x509.Certificate, error) {
	// Validates URL's certificate state
	var certChain []*x509.Certificate
	var certErr error
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err == nil {
		resp, err := v.Client.Do(req)
		certErr = err
		switch err {
		case nil:
			defer resp.Body.Close()
			certChain = resp.TLS.PeerCertificates
		default:
			var val WebValidator
			val.Init(true)
			certChain, _ = val.CheckWeb(url)
		}
	}
	return certChain, certErr
}

func CheckOCSP(commonName string, cert, issuerCert *x509.Certificate) (*ocsp.Response, error) {
	// Validates certificate revocation using OCSP
	var response *ocsp.Response
	opts := &ocsp.RequestOptions{Hash: crypto.SHA256}
	buffer, err := ocsp.CreateRequest(cert, issuerCert, opts)
	if err != nil {
		return response, err
	}
	if len(cert.OCSPServer) == 0 {
		return response, err
	}
	ocspServerURL := cert.OCSPServer[0]
	httpRequest, err := http.NewRequest(http.MethodPost, ocspServerURL, bytes.NewBuffer(buffer))
	if err != nil {
		return response, err
	}
	ocspURL, err := url.Parse(ocspServerURL)
	if err != nil {
		return response, err
	}
	fmt.Println(ocspURL)
	httpRequest.Header.Add("Content-Type", "application/ocsp-request")
	httpRequest.Header.Add("Accept", "application/ocsp-response")
	httpRequest.Header.Add("host", ocspURL.Host)
	httpClient := &http.Client{}
	httpResponse, err := httpClient.Do(httpRequest)
	if err != nil {
		return response, err
	}
	defer httpResponse.Body.Close()
	output, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		return response, err
	}
	response, err = ocsp.ParseResponseForCert(output, cert, issuerCert)
	return response, err
}

func RunCLI() {
	var c4w WebValidator
	var caSource, webUrl string

	app := &cli.App{
		Name:                 "C4W",
		Usage:                "CLI tool to validate Web",
		EnableBashCompletion: true,
		Action: func(c *cli.Context) error {
			return nil
		},
		Commands: []*cli.Command{
			{
				Name: "check",
				Action: func(cCtx *cli.Context) error {
					return nil
				},
				Subcommands: []*cli.Command{
					{
						Name: "tls",
						Action: func(cCtx *cli.Context) error {
							return nil
						},
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:        "tlscacert",
								Aliases:     []string{"ca"},
								Value:       "",
								Usage:       "Path to CA certs",
								Destination: &caSource,
								Required:    false,
							},
							&cli.StringFlag{
								Name:        "url",
								Aliases:     []string{"u"},
								Usage:       "Website's URL",
								Destination: &webUrl,
								Required:    true,
							},
						},
					},
				},
			},
		},
	}

	fmt.Println(webUrl)

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
	c4w.Init(false)

	switch caSource {
	case "":
		c4w.AddCert([]byte(ccadbRootCA))
		c4w.AddMozillaCA()
	default:
		caCerts, err := os.ReadFile(caSource)
		if err != nil {
			log.Fatal(err)
		}
		c4w.AddCert(caCerts)
	}

	certs, err := c4w.CheckWeb(webUrl)

	fmt.Println(err)

	// for _, cert := range certs {
	// 	fmt.Printf("DNS Names: %s\nValidity : %s - %s\nKey Algorithm: %s\nValid: %t\nURIs: %s\nOCSP: %s\nCLR: %s\n", cert.DNSNames, cert.NotBefore, cert.NotAfter, cert.PublicKeyAlgorithm.String(), cert.BasicConstraintsValid, cert.URIs, cert.OCSPServer, cert.CRLDistributionPoints)

	// 	// c4w.CheckCert(cert)
	// }
	url := webUrl
	if webUrl[0:8] == "https://" {
		url = webUrl[8:]
	}
	if url[len(url)-1:] == "/" {
		url = url[:len(url)-1]
	}

	if res, err := CheckOCSP(url, certs[0], certs[1]); err == nil {
		fmt.Println(res)
		fmt.Println(res.RevokedAt)
	}
}

func main() {
	RunCLI()
}
