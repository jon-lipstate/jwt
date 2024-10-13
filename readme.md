# JWT Library for Odin

This is a JSON Web Token (JWT) library written in Odin. It provides utilities for creating, signing, parsing, and verifying JWT tokens. It uses HMAC and SHA-based algorithms for token signing and verification.

Ref: [RFC7519](https://datatracker.ietf.org/doc/html/rfc7519)

## Usage

```odin
import "core:time"
import "core:crypto/hash"

KEY :: string("a super secret key")

User_Claims :: struct {
	user_id:    int,
	first_name: string,
	last_name:  string,
}

main :: proc() {
	signing_key := transmute([]u8)KEY

	// Token Creation:
	uc := User_Claims{3, "odie", "dog"}
	token, ok := make_token(hash.Algorithm.SHA256, uc, 1 * time.Hour)
	tk_str, sign_ok := sign_token(&token, signing_key)
	defer delete_token(&token)

	// Token Verification:
	tk := parse_token(tk_str, User_Claims, context.temp_allocator)
	defer delete_token(&tk)
	is_valid := verify_token(&tk, signing_key)

	fmt.println("is_valid", is_valid)

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