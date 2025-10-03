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
	"testing"

	"github.com/stretchr/testify/require"
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
