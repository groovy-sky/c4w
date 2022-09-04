package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
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

func (v *Validator) CheckCert(c *x509.Certificate) {
	fmt.Printf("%s | ", c.Subject.CommonName)

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

func (v *Validator) CheckWeb(url string) ([]*x509.Certificate, error) {
	// Validates URL's certificate state
	var certChain []*x509.Certificate
	var certErr error
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err == nil {
		resp, err := v.Client.Do(req)
		if err == nil {
			defer resp.Body.Close()
		}
		certChain = resp.TLS.PeerCertificates
		certErr = err
	}
	return certChain, certErr
	//resp, err := v.Client.Get(url)
	/*
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
				//certChain = conn.ConnectionState().VerifiedChains
			}
		} else {
			defer resp.Body.Close()
		}
		return resp.TLS.VerifiedChains, certErr
	*/
}

func main() {
	roots := x509.NewCertPool()

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: false, RootCAs: roots},
	}
	client := &http.Client{Transport: tr}
	w4c := Validator{roots, client}

	w4c.AddCert([]byte(ccadbRootCA))
	w4c.AddMozillaCerts()

	insecure := flag.Bool("insecure-ssl", true, "Accept/Ignore all server SSL certificates")
	flag.Parse()
	tr.TLSClientConfig.InsecureSkipVerify = *insecure

	certs, err := w4c.CheckWeb("https://untrusted-root.badssl.com/")
	opts := x509.VerifyOptions{
		Roots:   w4c.Roots,
		DNSName: "untrusted-root.badssl.com",
	}
	if _, err := certs[0].Verify(opts); err != nil {
		fmt.Println(err)
	}
	for _, cert := range certs {
		//fmt.Printf("DNS Names:\n\t%s\nValidity :\n\t%s - %s\nKey Algorithm:\n\t%s\nValid:\n\t%t\nURIs:\n\t%s\n\nOther:\n\t%s\n\n", cert.DNSNames, cert.NotBefore, cert.NotAfter, cert.PublicKeyAlgorithm.String(), cert.BasicConstraintsValid, cert.URIs, cert.CRLDistributionPoints)
		/*
			if _, err := cert.Verify(opts); err != nil {
				fmt.Println(err.Error())
			}
		*/
		w4c.CheckCert(cert)
	}
	fmt.Println(err)

}
