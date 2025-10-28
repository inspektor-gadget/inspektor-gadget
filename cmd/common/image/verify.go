package image

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/signature"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/signature/cosign"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/signature/notation"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/resources"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/oci"
)

func NewVerifyCmd() *cobra.Command {
	var notationCertificates string
	var authOpts oci.AuthOptions
	var cosignPublicKeys string
	var notationPolicy string
	var pullPolicy string

	cmd := &cobra.Command{
		Use:   "verify [gadget]",
		Short: "Verify gadget signature",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			image := args[0]

			verifier, err := signature.NewSignatureVerifier(signature.VerifierOptions{
				CosignVerifierOpts: cosign.VerifierOptions{
					PublicKeys: strings.Split(cosignPublicKeys, ","),
				},
				NotationVerifierOpts: notation.VerifierOptions{
					Certificates:   strings.Split(notationCertificates, ","),
					PolicyDocument: notationPolicy,
				},
			})

			fmt.Printf("Verifying image: %s\n", image)
			err = oci.EnsureImage(context.Background(), image, &oci.ImageOptions{
				AuthOptions: authOpts,
				VerifyOptions: oci.VerifyOptions{
					VerifySignature: true,
					Verifier:        verifier,
				},
			}, pullPolicy)
			if err != nil {
				return fmt.Errorf("verifying %q: %w", image, err)
			}
			fmt.Println("Image verified successfully!")

			return nil
		},
	}

	cmd.Flags().StringVar(&cosignPublicKeys, "public-keys", resources.InspektorGadgetPublicKey, "Public keys used to verify the gadgets with cosign")
	cmd.Flags().StringVar(&notationCertificates, "notation-certificates", "", "Certificates used to verify the gadgets with notation")
	cmd.Flags().StringVar(&notationPolicy, "notation-policy-document", "", "Policy Document used to verify the gadgets with notation")
	cmd.Flags().StringVar(&pullPolicy, "pull", oci.PullImageMissing, fmt.Sprintf("Specify when the gadget image should be pulled. Possible values are %v",strings.Join([]string{oci.PullImageAlways, oci.PullImageMissing, oci.PullImageNever}, ",")))
	utils.AddRegistryAuthVariablesAndFlags(cmd, &authOpts)

	return cmd
}
