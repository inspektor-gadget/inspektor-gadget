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

package signatureverifier

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/distribution/reference"
	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-core-go/signature/cose"
	"github.com/notaryproject/notation-core-go/signature/jws"
	nx509 "github.com/notaryproject/notation-core-go/x509"
	"github.com/notaryproject/notation-go/registry"
	"github.com/notaryproject/tspclient-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/registry/remote"
)

type NotationVerifyOptions struct {
	Certificates []string
}

type notationVerifier struct {
	certificates []string
}

// Taken from:
// https://github.com/notaryproject/notation-go/blob/e83edbc388a9/internal/envelope/envelope.go#L27C2-L28C2
const mediaTypePayloadV1 = "application/vnd.cncf.notary.payload.v1+json"

func getSignatures(ctx context.Context, repo *remote.Repository, imageStore oras.Target, ref reference.Named) (map[string][][]byte, error) {
	desc, err := imageStore.Resolve(ctx, ref.String())
	if err != nil {
		return nil, fmt.Errorf("resolving image %q: %w", ref, err)
	}

	signatures := map[string][][]byte{
		jws.MediaTypeEnvelope:  make([][]byte, 0),
		cose.MediaTypeEnvelope: make([][]byte, 0),
	}

	err = repo.Referrers(ctx, desc, registry.ArtifactTypeNotation, func(references []ocispec.Descriptor) error {
		for _, reference := range references {
			bytes, err := content.FetchAll(ctx, repo, reference)
			if err != nil {
				return fmt.Errorf("getting signature manifest bytes: %w", err)
			}

			signatureManifest := &ocispec.Manifest{}
			err = json.Unmarshal(bytes, signatureManifest)
			if err != nil {
				return fmt.Errorf("decoding signature manifest: %w", err)
			}

			for _, layer := range signatureManifest.Layers {
				if layer.MediaType != cose.MediaTypeEnvelope && layer.MediaType != jws.MediaTypeEnvelope {
					continue
				}

				signatureBytes, err := content.FetchAll(ctx, repo, layer)
				if err != nil {
					return fmt.Errorf("getting signature bytes: %w", err)
				}

				signatures[layer.MediaType] = append(signatures[layer.MediaType], signatureBytes)
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("ranging through referrers: %w", err)
	}

	return signatures, nil
}

// Inspired by:
// https://github.com/notaryproject/notation-go/blob/6063ebe30f96b0830e1385db4cdcdc24b0536d1a/verifier/verifier.go#L681
func verifyIntegrity(mediaTypeEnvelope string, signatureBytes []byte) (*signature.EnvelopeContent, error) {
	if mediaTypeEnvelope != cose.MediaTypeEnvelope && mediaTypeEnvelope != jws.MediaTypeEnvelope {
		return nil, fmt.Errorf("wrong media type envelope, expected %q or %q, got: %q", cose.MediaTypeEnvelope, jws.MediaTypeEnvelope, mediaTypeEnvelope)
	}

	envelope, err := signature.ParseEnvelope(mediaTypeEnvelope, signatureBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing envelope: %w", err)
	}

	content, err := envelope.Verify()
	if err != nil {
		return nil, fmt.Errorf("verifying envelope: %w", err)
	}

	if content.Payload.ContentType != mediaTypePayloadV1 {
		return nil, fmt.Errorf("bad payload content type, expected %q, got: %q", mediaTypePayloadV1, content.Payload.ContentType)
	}

	return content, nil
}

func revocationFinalResult(certResults []*revocationresult.CertRevocationResult, certChain []*x509.Certificate, logger log.Logger) (revocationresult.Result, string) {
	finalResult := revocationresult.ResultUnknown
	numOKResults := 0
	var problematicCertSubject string
	revokedFound := false
	var revokedCertSubject string
	for i := len(certResults) - 1; i >= 0; i-- {
		cert := certChain[i]
		certResult := certResults[i]
		if certResult.RevocationMethod == revocationresult.RevocationMethodOCSPFallbackCRL {
			// log the fallback warning
			logger.Warnf("OCSP check failed with unknown error and fallback to CRL check for certificate #%d in chain with subject %q", (i + 1), cert.Subject)
		}
		for _, serverResult := range certResult.ServerResults {
			if serverResult.Error != nil {
				// log individual server errors
				if certResult.RevocationMethod == revocationresult.RevocationMethodOCSPFallbackCRL && serverResult.RevocationMethod == revocationresult.RevocationMethodOCSP {
					// when the final revocation method is OCSPFallbackCRL,
					// the OCSP server results should not be logged as an error
					// since the CRL revocation check can succeed.
					logger.Debugf("Certificate #%d in chain with subject %q encountered an error for revocation method %s at URL %q: %v", (i + 1), cert.Subject, revocationresult.RevocationMethodOCSP, serverResult.Server, serverResult.Error)
					continue
				}
				logger.Errorf("Certificate #%d in chain with subject %q encountered an error for revocation method %s at URL %q: %v", (i + 1), cert.Subject, serverResult.RevocationMethod, serverResult.Server, serverResult.Error)
			}
		}

		if certResult.Result == revocationresult.ResultOK || certResult.Result == revocationresult.ResultNonRevokable {
			numOKResults++
		} else {
			finalResult = certResult.Result
			problematicCertSubject = cert.Subject.String()
			if certResult.Result == revocationresult.ResultRevoked {
				revokedFound = true
				revokedCertSubject = problematicCertSubject
			}
		}

		if i < len(certResults)-1 && certResult.Result == revocationresult.ResultNonRevokable {
			logger.Warnf("Certificate #%d in the chain with subject %q neither has an OCSP nor a CRL revocation method.", (i + 1), cert.Subject)
		}
	}
	if revokedFound {
		problematicCertSubject = revokedCertSubject
		finalResult = revocationresult.ResultRevoked
	}
	if numOKResults == len(certResults) {
		finalResult = revocationresult.ResultOK
	}
	return finalResult, problematicCertSubject
}

// Inspired by:
// https://github.com/notaryproject/notation-go/blob/e83edbc388a902c89bed4d84b1bb85084b4fcef7/verifier/verifier.go#L994
func verifyTimestamp(ctx context.Context, signerInfo *TODO) error {
	// 1. Timestamp countersignature MUST be present
	if len(signerInfo.UnsignedAttributes.TimestampSignature) == 0 {
		return errors.New("no timestamp countersignature was found in the signature envelope")
	}

	// 2. Verify the timestamp countersignature
	signedToken, err := tspclient.ParseSignedToken(signerInfo.UnsignedAttributes.TimestampSignature)
	if err != nil {
		return fmt.Errorf("parsing timestamp countersignature: %w", err)
	}
	info, err := signedToken.Info()
	if err != nil {
		return fmt.Errorf("getting the timestamp TSTInfo: %w", err)
	}
	timestamp, err := info.Validate(signerInfo.Signature)
	if err != nil {
		return fmt.Errorf("getting timestamp from timestamp countersignature: %w", err)
	}
	rootCertPool := x509.NewCertPool()
	for _, certificate := range certificates {
		rootCertPool.AddCert(trustedCerts)
	}
	tsaCertChain, err := signedToken.Verify(ctx, x509.VerifyOptions{
		CurrentTime: timestamp.Value,
		Roots:       rootCertPool,
	})
	if err != nil {
		return fmt.Errorf("verifying the timestamp countersignature: %w", err)
	}

	// 3. Validate timestamping certificate chain
	if err := nx509.ValidateTimestampingCertChain(tsaCertChain); err != nil {
		return fmt.Errorf("validating the timestamping certificate chain: %w", err)
	}

	// 4. Check the timestamp against the signing certificate chain
	for _, cert := range signerInfo.CertificateChain {
		if !timestamp.BoundedAfter(cert.NotBefore) {
			return fmt.Errorf("timestamp can be before certificate %q validity period, it will be valid from %q", cert.Subject, cert.NotBefore.Format(time.RFC1123Z))
		}
		if !timestamp.BoundedBefore(cert.NotAfter) {
			return fmt.Errorf("timestamp can be after certificate %q validity period, it was expired at %q", cert.Subject, cert.NotAfter.Format(time.RFC1123Z))
		}
	}

	// 5. Perform the timestamping certificate chain revocation check
	certResults, err := r.ValidateContext(ctx, revocation.ValidateContextOptions{
		CertChain: tsaCertChain,
	})
	if err != nil {
		return fmt.Errorf("checking timestamping certificate chain revocation with error: %w", err)
	}
	result, problematicCertSubject := revocationFinalResult(certResults, tsaCertChain, logger)
	switch result {
		case revocationresult.ResultOK:
			return nil
		case revocationresult.ResultRevoked:
			return fmt.Errorf("timestamping certificate with subject %q is revoked", problematicCertSubject)
		default:
			// revocationresult.ResultUnknown
			return fmt.Errorf("timestamping certificate with subject %q revocation status is unknown", problematicCertSubject)
	}
}

// Inspired by:
// https://github.com/notaryproject/notation-go/blob/e83edbc388a902c89bed4d84b1bb85084b4fcef7/verifier/verifier.go#L788
func verifyTimestampAuthenticity(ctx, context.Context, signerInfo *TODO) error {
	if signerInfo.SignedAttributes.SigningScheme == signature.SigningSchemeX509 {
		return verifyTimestamp(ctx, signerInfo)
	}

	authenticSigningTime := signerInfo.SignedAttributes.SigningTime
	for _, cert := range signerInfo.CertificateChain {
		if authenticSigningTime.Before(cert.NotBefore) || authenticSigningTime.After(cert.NotAfter) {
			return fmt.Errorf("certificate %q was not valid when the digital signature was produced at %q", cert.Subject, authenticSigningTime.Format(time.RFC1123Z))
		}
	}

	return nil
}

func (n *notationVerifier) Verify(ctx context.Context, repo *remote.Repository, imageStore oras.Target, ref reference.Named) error {
	certificates := make([]*x509.Certificate, len(n.certificates))
	for _, certificate := range n.certificates {
		block, _ := pem.Decode([]byte(certificate))
		if block == nil {
			return fmt.Errorf("decoding certificate to PEM blocks")
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("parsing certificate: %w", err)
		}

		certificates = append(certificates, cert)
	}

	signatures, err := getSignatures(ctx, repo, imageStore, ref)
	if err != nil {
		return fmt.Errorf("getting signature bytes: %w", err)
	}

	if len(signatures[jws.MediaTypeEnvelope]) == 0 && len(signatures[cose.MediaTypeEnvelope]) == 0 {
		return errors.New("no signatures were found")
	}

	for mediaTypeEnvelope, signaturesBytes := range signatures {
		for _, signatureBytes := range signaturesBytes {
			// Notation verifying has 5 steps:
			// 1. Integrity verifying.
			// 2. Authenticity verifying.
			// 3. Timestamp authenticity verifying.
			// 4. Expiry
			// 5. Revocation check
			// See:
			// https://github.com/notaryproject/specifications/blob/main/specs/trust-store-trust-policy.md#signature-verification-details

			content, err := verifyIntegrity(mediaTypeEnvelope, signatureBytes)
			if err != nil {
				return fmt.Errorf("verifying envelope integrity: %w", err)
			}

			signerInfo := &content.SignerInfo
			_, err = signature.VerifyAuthenticity(&signerInfo, certificates)
			if err != nil {
				return fmt.Errorf("verifying signature authenticity: %w", err)
			}

			err := verifyTimestampAuthenticity(ctx, signerInfo)
			if err != nil {
				return fmt.Errorf("verifying timestamp authenticity: %w", err)

			}

		}
	}

	return nil
}
