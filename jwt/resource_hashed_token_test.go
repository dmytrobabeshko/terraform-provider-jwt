package jwt

import (
	"fmt"
	"testing"

	r "github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestHashedJWT(t *testing.T) {
	t.Setenv("TF_ACC", "1")

	r.Test(t, r.TestCase{
		Providers: testProviders,
		Steps: []r.TestStep{
			{
				Config: `
resource "jwt_hashed_token" "example" {
	algorithm = "HS512"
	secret    = "notthegreatestkey"

	claims_json = jsonencode({
		a = "b"
	})
}

output "example_token" {
	sensitive = true
	value = "${jwt_hashed_token.example.token}"
}
`,
				Check: func(s *terraform.State) error {
					gotTokenUntyped := s.RootModule().Outputs["example_token"].Value
					gotToken, ok := gotTokenUntyped.(string)
					if !ok {
						return fmt.Errorf("Output for \"example_token\" is not a string.")
					}

					if gotToken != "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJhIjoiYiJ9.cl5DXDjjNUqWzYcsSOvljSs9skgxV7xrxXr6IFXdN_FEYe7qOw-IsWBQBAyB1Ra3kfngwT9h2VK1YuT00Qp-rg" {
						return fmt.Errorf("Token miscalculated.")
					}

					return nil
				},
			},
			{
				Config: `
resource "jwt_hashed_token" "base64_example" {
	algorithm       = "HS512"
	secret          = "ZX92vEaSMKXYAIF127SewQ=="
	secret_encoding = "base64"

	claims_json = jsonencode({
		a = "b"
	})
}

output "base64_example_token" {
	sensitive = true
	value     = "${jwt_hashed_token.base64_example.token}"
}
`,
				Check: func(s *terraform.State) error {
					gotTokenUntyped := s.RootModule().Outputs["base64_example_token"].Value
					gotToken, _ := gotTokenUntyped.(string)

					if gotToken != "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJhIjoiYiJ9.zQB7DzBc37wOq-tsyDer8EysaWNEwA8rYq9fXFgWO9giMIkRwdCUYTUO27kY3nYFyDYRnVBMfOOYJ7X-l7LEIA" {
						return fmt.Errorf("Token miscalculated.")
					}

					return nil
				},
			},
		},
	})
}
