# JWT Library for Odin

This is a JSON Web Token (JWT) library written in Odin. It provides utilities for creating, signing, parsing, and verifying JWT tokens. It uses HMAC and SHA-based algorithms for token signing and verification.

Ref: [RFC7519](https://datatracker.ietf.org/doc/html/rfc7519)

## Usage

```odin
import "core:time"
import "core:crypto/hash"

KEY :: string("a super secret key")

main :: proc() {
	signing_key := transmute([]u8)KEY

	// Token Creation:
	claims := map[string]Value {
		"user_id" = 3,
	}
	defer delete(claims)

	token, ok := make_token(hash.Algorithm.SHA256, claims, 1 * time.Hour)
	tk_str, sign_ok := sign_token(&token, signing_key)
	defer delete_token(&token)

	// Token Verification:
	tk := parse_token(tk_str, context.temp_allocator) // Unmarshall allocates here, you should either use temp_allocator or another custom allocator to keep this from leaking
	defer delete_token(&tk)
	is_valid := verify_token(&tk, signing_key) // several temp_allocator uses here

	free_all(context.temp_allocator)
}
```

## API

`make_token`: generates a token struct

`sign_token`: signs the struct, prepares token string

`parse_token`: converts a token-string back into a struct

`verify_token`: ensures the signing matches and the token is not expired

## License
This library is open source under the BSD-3 license.