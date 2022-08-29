package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"net/http"
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

type Validator struct {
	Roots  *x509.CertPool
	Client *http.Client
}

func (v *Validator) AddCert(cert []byte) {
	// Appends CA store
	v.Roots.AppendCertsFromPEM(cert)
}

func (v *Validator) AddMozillaCerts() {
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

func (v *Validator) CheckWeb(url string) ([][]*x509.Certificate, error) {
	// Validates URL's certificate state
	var certChain [][]*x509.Certificate
	var certErr error
	resp, err := v.Client.Get(url)
	certErr = err
	if err != nil {
		if url[0:8] == "https://" {
			url = url[8:]
		}
		if url[len(url)-1:] == "/" {
			url = url[:len(url)-1]
		}
		url = url + ":443"
		fmt.Println(url)
		conn, tlserr := tls.Dial("tcp", url, nil)
		if tlserr != nil {
			certErr = fmt.Errorf("%w; %w", certErr, tlserr)
		} else {
			defer conn.Close()
			certChain = conn.ConnectionState().VerifiedChains
		}
	} else {
		defer resp.Body.Close()
		certChain = resp.TLS.VerifiedChains
	}
	return certChain, certErr
}

func main() {
	roots := x509.NewCertPool()

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: false, RootCAs: roots},
	}
	client := &http.Client{Transport: tr}
	wcv := Validator{roots, client}

	wcv.AddCert([]byte(ccadbRootCA))
	wcv.AddMozillaCerts()

	resp, err := wcv.CheckWeb("https://expired.badssl.com/")
	fmt.Println(resp)
	fmt.Println(err)

}
