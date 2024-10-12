package jwt

import "core:crypto"
import "core:crypto/hash"
import "core:crypto/hmac"
import "core:encoding/base64"
import "core:encoding/json"
import "core:fmt"
import "core:mem"
import "core:strings"
import "core:time"
//
main :: proc() {
	tracker: mem.Tracking_Allocator
	mem.tracking_allocator_init(&tracker, context.allocator)
	context.allocator = mem.tracking_allocator(&tracker)
	_main()

	if len(tracker.allocation_map) > 0 {
		fmt.println()
		for _, v in tracker.allocation_map {
			fmt.printf("%v Leaked %v bytes.\n", v.location, v.size)
		}
	} else {
		fmt.println("Hooray! no memory leaks")
	}
}


KEY :: string("a super secret key")

_main :: proc() {
	signing_key := transmute([]u8)KEY

	// Token Creation:
	// TODO: not in love with json interface for claims, make custom union or..?
	roles := json.Array{"admin", "user"}
	defer delete(roles)
	claims := map[string]Value {
		"user_id" = 3,
		"roles"   = roles,
	}
	defer delete(claims)

	token, ok := make_token(hash.Algorithm.SHA256, claims, 1 * time.Hour)
	tk_str, sign_ok := sign_token(&token, signing_key)
	defer delete_token(&token)

	// Token Verification:
	tk := parse_token(tk_str, context.temp_allocator)
	defer delete_token(&tk)
	is_valid := verify_token(&tk, signing_key)

	free_all(context.temp_allocator)
}

Error :: union {} // TODO:

Value :: json.Value
Algorithm :: hash.Algorithm

Token :: struct {
	using base: Base_Token,
	claims:     map[string]Value,
}

Base_Token :: struct {
	str:       string,
	method:    Algorithm,
	header:    map[string]Value,
	signature: []byte,
	is_valid:  bool,
}

//<base64url(header)>.<base64url(payload)>.<signature>
delete_token :: proc(t: ^Token) {
	delete(t.header)
	delete(t.signature)
	delete(t.str)
}
make_token :: proc(
	alg: Algorithm,
	claims: map[string]Value,
	expires_in: time.Duration,
) -> (
	token: Token,
	ok: bool,
) {

	alg_str, found := alg_to_str(alg)
	if !found {
		fmt.eprintln("make_token: Invalid/Unimplemented Algorithm Supplied")
		return {}, false
	}
	token = Token {
		base = {
			method = alg,
			header = map[string]Value{"alg" = alg_str, "typ" = "JWT"},
			signature = nil,
			is_valid = false,
		},
		claims = claims,
	}
	exp := into_seconds_from_now(expires_in)
	token.claims["exp"] = exp

	return token, true
}

sign_token :: proc(token: ^Token, key: []u8) -> (token_string: string, ok: bool) {
	header_json, _ := json.marshal(
		token.header,
		json.Marshal_Options{sort_maps_by_key = true},
		allocator = context.temp_allocator,
	)
	claims_json, _ := json.marshal(
		token.claims,
		json.Marshal_Options{sort_maps_by_key = true},
		allocator = context.temp_allocator,
	)
	header_base64, _ := base64.encode(
		transmute([]byte)header_json,
		allocator = context.temp_allocator,
	)
	claims_base64, _ := base64.encode(
		transmute([]byte)claims_json,
		allocator = context.temp_allocator,
	)

	signing_input := strings.join(
		{header_base64, claims_base64},
		".",
		allocator = context.temp_allocator,
	)
	sig_bytes, _ := mem.make_aligned([]byte, hash.DIGEST_SIZES[token.base.method], 16) // RETAIN
	token.signature = sig_bytes

	hmac.sum(token.base.method, token.signature, transmute([]byte)signing_input, key)

	signature_base64, _ := base64.encode(token.signature, allocator = context.temp_allocator)

	token.str = strings.join(
		{signing_input, signature_base64},
		".",
		allocator = context.allocator,
	) // RETAIN
	token.is_valid = true

	free_all(context.temp_allocator)
	return token.str, true
}

into_seconds_from_now :: proc(d: time.Duration) -> i64 {
	return time.to_unix_seconds(time.time_add(time.now(), d))
}

// WARNING: unmarshall will leak if you dont free it, strongly suggest an Arena or other clearable allocator
parse_token :: proc(str: string, allocator := context.allocator) -> Token {

	parts := strings.split(str, ".", allocator = context.temp_allocator)
	if len(parts) != 3 {
		panic("Invalid token structure. Expected 3 parts.")
	}

	header_bytes, _ := base64.decode(parts[0], allocator = context.temp_allocator)
	claims_bytes, _ := base64.decode(parts[1], allocator = context.temp_allocator)
	signature_bytes, _ := base64.decode(parts[2], allocator = allocator) // RETAIN
	token := Token {
		base = Base_Token {
			str       = str,
			method    = hash.Algorithm.SHA256, // FIXME: read method from header!!
			header    = map[string]Value{}, // RETAIN
			signature = signature_bytes,
			is_valid  = false,
		},
		claims = map[string]Value{}, // RETAIN
	}

	json.unmarshal(header_bytes, &token.header, allocator = allocator) // RETAIN
	json.unmarshal(claims_bytes, &token.claims, allocator = allocator) // RETAIN

	// free_all(context.temp_allocator)

	return token
}

verify_token :: proc(token: ^Token, key: []u8, allocator := context.allocator) -> bool {
	header_json, _ := json.marshal(
		token.header,
		json.Marshal_Options{sort_maps_by_key = true},
		allocator = context.temp_allocator,
	)
	claims_json, _ := json.marshal(
		token.claims,
		json.Marshal_Options{sort_maps_by_key = true},
		allocator = context.temp_allocator,
	)

	header_base64, _ := base64.encode(
		transmute([]byte)header_json,
		allocator = context.temp_allocator,
	)
	claims_base64, _ := base64.encode(
		transmute([]byte)claims_json,
		allocator = context.temp_allocator,
	)

	signing_input := strings.join(
		{header_base64, claims_base64},
		".",
		allocator = context.temp_allocator,
	)

	computed_signature, _ := mem.make_aligned(
		[]byte,
		hash.DIGEST_SIZES[token.base.method],
		16,
		allocator = context.temp_allocator,
	)

	hmac.sum(token.base.method, computed_signature, transmute([]byte)signing_input, key)

	token.is_valid = crypto.compare_constant_time(computed_signature, token.signature) == 1

	token.is_valid &= !is_token_expired(token)

	return token.is_valid
}
// seconds resolution
is_token_expired :: proc(t: ^Token) -> bool {
	assert(t.claims != nil, "Nil claims map on Token")

	exp, has_exp := t.claims["exp"].(json.Integer)
	if !has_exp {return true}

	diff := time.diff(time.now(), time.Time{exp * 1E9})
	is_expired := int(diff / 1E9) < 0
	return is_expired
}

@(private)
alg_to_str :: proc(alg: Algorithm) -> (name: string, found: bool) {
	for k, v in JWT_ALGORITHM_MAP {
		if alg == v {return k, true}
	}
	return "", false
}
JWT_ALGORITHM_MAP := map[string]Algorithm {
	"HS256"      = Algorithm.SHA256, // HMAC with SHA-256
	"HS384"      = Algorithm.SHA384, // HMAC with SHA-384
	"HS512"      = Algorithm.SHA512, // HMAC with SHA-512
	// "RS256"      = Algorithm.Invalid, // RSA with SHA-256 (not implemented)
	// "RS384"      = Algorithm.Invalid, // RSA with SHA-384 (not implemented)
	// "RS512"      = Algorithm.Invalid, // RSA with SHA-512 (not implemented)
	// "ES256"      = Algorithm.Invalid, // ECDSA with P-256 and SHA-256 (not implemented)
	// "ES384"      = Algorithm.Invalid, // ECDSA with P-384 and SHA-384 (not implemented)
	// "ES512"      = Algorithm.Invalid, // ECDSA with P-521 and SHA-512 (not implemented)
	// "PS256"      = Algorithm.Invalid, // RSASSA-PSS with SHA-256 (not implemented)
	// "PS384"      = Algorithm.Invalid, // RSASSA-PSS with SHA-384 (not implemented)
	// "PS512"      = Algorithm.Invalid, // RSASSA-PSS with SHA-512 (not implemented)
	"SHA256"     = Algorithm.SHA256, // SHA-256
	"SHA384"     = Algorithm.SHA384, // SHA-384
	"SHA512"     = Algorithm.SHA512, // SHA-512
	"SHA512_256" = Algorithm.SHA512_256, // SHA-512/256
	"SHA3_256"   = Algorithm.SHA3_256, // SHA3-256
	"SHA3_384"   = Algorithm.SHA3_384, // SHA3-384
	"SHA3_512"   = Algorithm.SHA3_512, // SHA3-512
	"SM3"        = Algorithm.SM3, // SM3 (China's cryptographic hash function)
	"BLAKE2b"    = Algorithm.BLAKE2B, // BLAKE2b
	"BLAKE2s"    = Algorithm.BLAKE2S, // BLAKE2s
}
