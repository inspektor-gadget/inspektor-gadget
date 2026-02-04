// Copyright 2025 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package notation

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/distribution/reference"
	"github.com/stretchr/testify/require"
	"oras.land/oras-go/v2/content/oci"
)

func TestNewVerifier(t *testing.T) {
	t.Parallel()

	type testDefinition struct {
		opts      VerifierOptions
		shouldErr bool
	}

	goodPolicyDocument := `
{
    "version": "1.0",
    "trustPolicies": [
        {
            "name": "inspektor-gadget-policy",
            "registryScopes": [ "*" ],
            "signatureVerification": {
              "level" : "strict"
            },
            "trustStores": ["ca:inspektor-gadget.io"],
            "trustedIdentities": [
              "x509.subject: CN=inspektor-gadget.io, O=Notary, L=Seattle, ST=WA, C=US"
            ]
        }
    ]
}
`

	goodCertificate := `
-----BEGIN CERTIFICATE-----
MIIDRTCCAi2gAwIBAgICAIEwDQYJKoZIhvcNAQELBQAwUTELMAkGA1UEBhMCVVMx
CzAJBgNVBAgTAldBMRAwDgYDVQQHEwdTZWF0dGxlMQ8wDQYDVQQKEwZOb3Rhcnkx
EjAQBgNVBAMTCWJhcmZvby5pbzAeFw0yNTEwMDExNTQ2MzVaFw0yNTEwMDIxNTQ2
MzVaMFExCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJXQTEQMA4GA1UEBxMHU2VhdHRs
ZTEPMA0GA1UEChMGTm90YXJ5MRIwEAYDVQQDEwliYXJmb28uaW8wggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDirG5+wdavupHd+K3M4hvPAzQu1NE6Edur
VsptZTBXnZNCT3/rVlzIF6uoExUe9k8xdBV86aVlI1KUKXb3jWtq4u+9ACcmZ3nO
+JzhkOZEGN7XTf7axDWIZWv5mye655shIwtLrrguNBs+0lXqO+x5uImqdGtjgH5S
RrDpHzSNiRziyqym1fCgJI3lwO/sWIZK+2oJLPvCYzS4k0sNo50wB6JI+Eu/qtBK
c0OCXLhKr0ml9bRpDaoMyIhQrD0+k5JWSDPlNCwIEYueJpf3Ua38YuuM3pPEj8MA
/hzEyrFpqeJV2Nn5JHRjAecSZbFRHyRtzETn9NKaz00EnoE3/O3nAgMBAAGjJzAl
MA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzANBgkqhkiG9w0B
AQsFAAOCAQEANjfgsg6Zxc/g+8T3ZLNMj0myd8yciiL16iS4+LQKViRGNmAjRbic
eslrAFXSiZHI/RIJxKnQBxtDiXs8UlknV2mLnxZP+S2vk3kW/z0w6gRPRC8t3w3K
BcsDhE//PzLmnXdEYSZQvgXfdv2JujEb1euspyTjRL1vBlxdPh5eeevZsysHrt6q
c2bFCX/8nicguibCC4ybKQazsbQK07tIPDwlbu0+sCk6ojmhdMZeOaXVcUoaisgq
dKl8IemhdshLNii2f05fLb1ftcMaG0XIT7i86txiDbiBs+srcjW4bqfhSc201jHu
/ftuKYyrrWBgnWZ6gmzqC5SR4pBdZVAp3w==
-----END CERTIFICATE-----
`

	tests := map[string]testDefinition{
		"no_policy_document_and_no_certificates": {
			shouldErr: true,
		},
		"no_policy_document": {
			opts: VerifierOptions{
				Certificates: []string{goodCertificate},
			},
			shouldErr: true,
		},
		"no_certificates": {
			opts: VerifierOptions{
				PolicyDocument: goodPolicyDocument,
			},
			shouldErr: true,
		},
		"policy_document_with_several_trust_stores": {
			opts: VerifierOptions{
				Certificates: []string{goodCertificate},
				PolicyDocument: `
{
	"version": "1.0",
	"trustPolicies": [
		{
			"name": "inspektor-gadget-policy",
			"registryScopes": [ "*" ],
			"signatureVerification": {
				"level" : "strict"
			},
			"trustStores": ["ca:inspektor-gadget.io", "ca:foobar.io"],
			"trustedIdentities": [
				"x509.subject: CN=inspektor-gadget.io, O=Notary, L=Seattle, ST=WA, C=US"
			]
		}
	]
}
`,
			},
			shouldErr: true,
		},
		"ok": {
			opts: VerifierOptions{
				Certificates:   []string{goodCertificate},
				PolicyDocument: goodPolicyDocument,
			},
		},
	}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := NewVerifier(test.opts)
			if test.shouldErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
		})
	}
}

func TestVerify(t *testing.T) {
	t.Parallel()

	type testDefinition struct {
		opts      VerifierOptions
		image     string
		shouldErr bool
	}

	// Signed with older notation, i.e. 6c5c35a0207eebf8d4d6d2efad66b798457a6622:
	// {
	// "schemaVersion": 2,
	// "mediaType": "application/vnd.oci.image.manifest.v1+json",
	// "config": {
	// 	"mediaType": "application/vnd.cncf.notary.signature",
	// ...
	firstSignedImage := "ttl.sh/signed_with_notation_config_media_type_signature:latest"
	// Signed with newer notation, i.e. a71c2d9d879cbdf219cb82814f8779d1a60403bf:
	// {
	// "schemaVersion": 2,
	// "mediaType": "application/vnd.oci.image.manifest.v1+json",
	// "artifactType": "application/vnd.cncf.notary.signature",
	// "config": {
	// 	"mediaType": "application/vnd.oci.empty.v1+json",
	// ...
	secondSignedImage := "ttl.sh/signed_with_notation_config_media_type_empty:latest"
	nonSignedImage := "ghcr.io/inspektor-gadget/gadget/unsigned:francis-signature-unit-tests"

	goodCertificate := `
-----BEGIN CERTIFICATE-----
MIIDQDCCAiigAwIBAgIBHjANBgkqhkiG9w0BAQsFADBPMQswCQYDVQQGEwJVUzEL
MAkGA1UECBMCV0ExEDAOBgNVBAcTB1NlYXR0bGUxDzANBgNVBAoTBk5vdGFyeTEQ
MA4GA1UEAxMHdGVzdC5pbzAeFw0yNjAxMjAxNDQwNTNaFw0yNjAxMjExNDQwNTNa
ME8xCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJXQTEQMA4GA1UEBxMHU2VhdHRsZTEP
MA0GA1UEChMGTm90YXJ5MRAwDgYDVQQDEwd0ZXN0LmlvMIIBIjANBgkqhkiG9w0B
AQEFAAOCAQ8AMIIBCgKCAQEAtlupXrTX7KVO7rFc+6Cn27dKF43gczIGYoxzCGeO
G7UrNq+AsnBvHjZAZDPe2LIhK+E+pQGGXnWgA9y6hUIHrkffH4jwhSiGZiQL6rAl
dSKFOG1FCEkfA9TsKCs7RCR8mSCxn4H0JsldF1mv8z7MlzAvGhoszeD6sEfsgqWK
og3LTmRxmqWMKJar1wOdpXLLquKRbgHhNMFLE9eiekeqndb365kv/32h3PtzFMga
Y8fDKrbmPRS5dloR2gWNm6kizU3sns0GbDVpReQolTrYEZNXQWm4hY7urfU1eBXe
A2XqOLbB9WNx5fS1rrTIdlo7QYMQoOwLoNHcMXd6BKElpQIDAQABoycwJTAOBgNV
HQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwMwDQYJKoZIhvcNAQELBQAD
ggEBABRsxy2tnl1D2WmI2I/3wFa0+AnzEhAN3by0B3QfSBa4uYUJzeFfT+ImMjvA
/cuDe/J4MXgkZiCQmSfC51lIEOZH73TX988h1CLAgnWAvUqTavnof2uOqlhSFsGf
OgEmUMA9Cek0YAvIsD9hPxQLQpMjDkfwLVcLmEgiGaSaB3wX94H+iio/hgE8iems
Rmxuh0CWu/yOhFY2HMoyHl448fAqfg1dIDP4N29HBD9oOPtmVN1rGksMpl9fyxWL
EPUwm6JVfxOUj/5d6HCpIA674eNGXeGmaXBnc2GdGwhBE+zLmOozim+tjheza3H7
rJ/aJWNv7+e5taVw6EYyA9eT8L4=
-----END CERTIFICATE-----
`

	wrongCertificate := `
-----BEGIN CERTIFICATE-----
MIIDPzCCAiegAwIBAgICAK8wDQYJKoZIhvcNAQELBQAwTjELMAkGA1UEBhMCVVMx
CzAJBgNVBAgTAldBMRAwDgYDVQQHEwdTZWF0dGxlMQ8wDQYDVQQKEwZOb3Rhcnkx
DzANBgNVBAMTBnh5ei5pbzAeFw0yNTEwMTMwNjA1NDdaFw0yNTEwMTQwNjA1NDda
ME4xCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJXQTEQMA4GA1UEBxMHU2VhdHRsZTEP
MA0GA1UEChMGTm90YXJ5MQ8wDQYDVQQDEwZ4eXouaW8wggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQC6WP0d7ap9RUxlKhCdiqdNmXTDprvPp/gtKFWmRXeX
CnvrvTpWixLcLwIFpFIchsELQGXxaDK9sUUBtauUJs9DSKSDssYvazw5Ige/FNCw
KPtXJj3ax7m0uP4LzQXHHb5Nnbd2BlGk2a3FfXZ/kkia5n6AN8Z91CxJAoUE/ZhR
zBhBgvsWcAcijsBUhn1LDepL36D+rQMNvYrJf0HeXUVoWDvZBLmkKVHtEpKbZF1Z
kKsMvTA8JoB+DLTB2A2nav01Q0+Pbb220ZX+tyD/LhP9nk9WFlx4rF9XVSOvbG/H
c+OW2Fb7PYQJN0oVBKYJ4/xAc5L56aXGeto47+RuSrjNAgMBAAGjJzAlMA4GA1Ud
DwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzANBgkqhkiG9w0BAQsFAAOC
AQEAtaV2DGbA+2QZTNJ5uUZ66th6J6A+H07sP5GCz4NJnB7Cm5pyuAH+U6o7KHm8
eCx00K5OZP9jmPpbdo2KWHnrEHbHJKrj+Z3O0BF7zfVtxZYPO92Bd/CqWiGw6KXo
wJU2ASNZov+cuJ7IbIP1LMhMT4LPpIdZqrZrcs3bzdAugSkn5mzTjIIYj5wEV3EH
MEVMSuuHVRyeJBqEb0K9kLQVSLSv6kzRf5NFjmx1ZwK7jgnvRw381yFjtptSos/B
W17wNW922h7x1L++XnMi/HBZcwMDwYHNW4QMwbf5bjBlWWYBB5mq1aQ/9GGGE1On
S//euSjbohacaQzTb8ZQqRLKfg==
-----END CERTIFICATE-----
`

	// Use permissive instead of strict to avoid the unit tests failing when the
	// certificate will be expired.
	policyDocument := `
{
    "version": "1.0",
    "trustPolicies": [
        {
            "name": "test-policy",
            "registryScopes": [ "*" ],
            "signatureVerification": {
              "level" : "permissive"
            },
            "trustStores": ["ca:test.io"],
            "trustedIdentities": [
              "x509.subject: CN=test.io, O=Notary, L=Seattle, ST=WA, C=US"
            ]
        }
    ]
}
`

	tests := map[string]testDefinition{
		"good_certificate_with_first_signed_image": {
			opts: VerifierOptions{
				Certificates:   []string{goodCertificate},
				PolicyDocument: policyDocument,
			},
			image: firstSignedImage,
		},
		"good_certificate_with_second_signed_image": {
			opts: VerifierOptions{
				Certificates:   []string{goodCertificate},
				PolicyDocument: policyDocument,
			},
			image: secondSignedImage,
		},
		"wrong_certificate_with_signed_image": {
			opts: VerifierOptions{
				Certificates:   []string{wrongCertificate},
				PolicyDocument: policyDocument,
			},
			image:     firstSignedImage,
			shouldErr: true,
		},
		"certificate_with_unsigned_image": {
			opts: VerifierOptions{
				Certificates:   []string{wrongCertificate},
				PolicyDocument: policyDocument,
			},
			image:     nonSignedImage,
			shouldErr: true,
		},
		"several_certificates_with_signed_image": {
			opts: VerifierOptions{
				Certificates: []string{
					wrongCertificate,
					goodCertificate,
				},
				PolicyDocument: policyDocument,
			},
			image: firstSignedImage,
		},
	}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			store, err := oci.New(filepath.Join("..", "..", "testdata", "oci-store"))
			require.NoError(t, err)

			ref, err := reference.ParseNormalizedNamed(test.image)
			require.NoError(t, err)
			ref = reference.TagNameOnly(ref)

			verifier, err := NewVerifier(test.opts)
			require.NoError(t, err)

			err = verifier.Verify(context.Background(), store, ref)
			if test.shouldErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
		})
	}
}
