package image

import (
	"context"
	"fmt"

	"github.com/distribution/reference"
	"github.com/spf13/cobra"
	"oras.land/oras-go/v2/registry/remote"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/signature"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/signature/cosign"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/signature/notation"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/resources"
)

func NewVerifyCmd() *cobra.Command {
	var publicKeys []string
	var certificates []string
	var policy string

	cmd := &cobra.Command{
		Use:   "verify [gadget]",
		Short: "Verify gadget signature",

		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			imageRef := args[0]

			verifier, err := signature.NewSignatureVerifier(signature.VerifierOptions{
				CosignVerifierOpts: cosign.VerifierOptions{
					PublicKeys: publicKeys,
				},
				NotationVerifierOpts: notation.VerifierOptions{
					Certificates:   certificates,
					PolicyDocument: policy,
				},
			})
			if err != nil {
				return fmt.Errorf("initializing verifier: %w", err)
			}

			fmt.Printf("Verifying image: %s\n", imageRef)

			ref, err := reference.ParseNormalizedNamed(imageRef)
			if err != nil {
				return fmt.Errorf("invalid image reference: %w", err)
			}

			repo, err := remote.NewRepository(reference.FamiliarName(ref))
			if err != nil {
				return fmt.Errorf("creating repository: %w", err)
			}

			if err := verifier.Verify(ctx, repo, repo, ref); err != nil {
				return fmt.Errorf("verifying %q: %w", imageRef, err)
			}

			fmt.Println("Image verified successfully!")
			return nil
		},
	}

	cmd.Flags().StringSliceVar(&publicKeys, "public-keys", []string{resources.InspektorGadgetPublicKey}, "Public keys used to verify the gadgets with cosign")
	cmd.Flags().StringSliceVar(&certificates, "notation-certificates", nil, "Certificates used to verify the gadgets with notation")
	cmd.Flags().StringVar(&policy, "notation-policy-document", "", "Policy Document used to verify the gadgets with notation")

	return cmd
}
