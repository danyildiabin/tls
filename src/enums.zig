/// TLS Record type
pub const ContentType = enum(u8) {
    invalid = 0,
    change_cipher_spec = 20,
    alert = 21,
    handshake = 22,
    application_data = 23,
    heartbeat = 24,
    _,
};

pub const CompressedY = enum(u8) {
    even = 2,
    odd = 3,
    _,
};

pub const HashAlgorithm = enum(u8) {
    none = 0,
    md5 = 1,
    sha1 = 2,
    sha224 = 3,
    sha256 = 4,
    sha384 = 5,
    sha512 = 6,
    _,
};

pub const SignatureAlgorithm = enum(u8) {
    anonymous = 0,
    rsa = 1,
    dsa = 2,
    ecdsa = 3,
    _,
};

pub const ECCurveType = enum(u8) {
    explicit_prime = 1, // deprecated
    explicit_char2 = 2, // deprecated
    named_curve = 3,
    _,
};

// 1. PROTOCOL
// 2. KEY_EXCHANGE_ALGORITHM
// 3. DIGITAL_SIGNATURE_ALGORITHM
// 4. BULK_ENCRYPTION_ALGORITHM
// 5. HASHING_ALGORITHM

// ECDHE - Elliptic Curve Diffie-Hellman Ephemeral
// ECDSA - Elliptic Curve Digital Signature Algorithm
// GCM - Galois/Counter mode
// AES - Advanced encryption standard
// SHA - Secure Hash Algorithm
// CBC - Cipher Block Chaining
// RSA - Rivest Shamir Adleman algorithm

/// CipherSuites formated as IANA names
pub const CipherSuite = enum(u16) {
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xC02B, // Recommended
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xC02C, // Recommended
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = 0xC023, // Weak
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = 0xC024, // Weak
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xC02F, // Secure
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xC030, // Secure
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 = 0xC027, // Weak
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 = 0xC028, // Weak
    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 = 0x009E, // Secure
    TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 = 0x009F, // Secure
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA = 0x0033, // Weak
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA = 0x0039, // Weak
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = 0x0067, // Weak
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 = 0x006B, // Weak
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCA9, // Recommended
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCA8, // Secure
    _,
};

/// ClientHello/ServerHello Extension types
pub const ExtensionType = enum(u16) {
    server_name = 0,
    status_request = 5,
    supported_groups = 10,
    supported_formats = 11,
    _,
};

/// Levels of alert record
pub const AlertLevel = enum(u8) {
    warning = 1,
    fatal = 2,
    _,
};

/// Short description of alerts
pub const AlertDescription = enum(u8) {
    close_notify = 0,
    unexpected_message = 10,
    bad_record_mac = 20,
    decryption_failed = 21,
    record_overflow = 22,
    decompression_failure = 30,
    handshake_failure = 40,
    no_certificate = 41,
    bad_certificate = 42,
    unsupported_certificate = 43,
    certificate_revoked = 44,
    certificate_expired = 45,
    certificate_unknown = 46,
    illegal_parameter = 47,
    unknown_ca = 48,
    access_denied = 49,
    decode_error = 50,
    decrypt_error = 51,
    export_restriction = 60,
    protocol_version = 70,
    insufficient_security = 71,
    internal_error = 80,
    inappropriate_fallback = 86,
    user_canceled = 90,
    no_renegotiation = 100,
    missing_extension = 109,
    unsupported_extension = 110,
    certificate_unobtainable = 111,
    unrecognized_name = 112,
    bad_certificate_status_response = 113,
    bad_certificate_hash_value = 114,
    unknown_psk_identity = 115,
    certificate_required = 116,
    no_application_protocol = 120,
    _,
};

/// Type of handshake message
pub const HandshakeType = enum(u8) {
    hello_request = 0,
    client_hello = 1,
    server_hello = 2,
    new_session_ticket = 4,
    end_of_early_data = 5,
    encrypted_extensions = 8,
    certificate = 11,
    server_key_exchange = 12,
    certificate_request = 13,
    server_hello_done = 14,
    certificate_verify = 15,
    client_key_exchange = 16,
    finished = 20,
    certificate_url = 21,
    certificate_status = 22,
    key_update = 24,
    message_hash = 254,
    _,
};

/// TLS versions
pub const Version = enum(u16) {
    SSL_3_0 = 0x0300,
    TLS_1_0 = 0x0301,
    TLS_1_1 = 0x0302,
    TLS_1_2 = 0x0303,
    TLS_1_3 = 0x0304,
    _,
};

/// Named eliptic curves codes
pub const EllipticCurve = enum(u16) {
    sect163k1 = 1,  // deprecated
    sect163r1 = 2,  // deprecated
    sect163r2 = 3,  // deprecated
    sect193r1 = 4,  // deprecated
    sect193r2 = 5,  // deprecated
    sect233k1 = 6,  // deprecated
    sect233r1 = 7,  // deprecated
    sect239k1 = 8,  // deprecated
    sect283k1 = 9,  // deprecated
    sect283r1 = 10, // deprecated
    sect409k1 = 11, // deprecated
    sect409r1 = 12, // deprecated
    sect571k1 = 13, // deprecated
    sect571r1 = 14, // deprecated
    secp160k1 = 15, // deprecated
    secp160r1 = 16, // deprecated
    secp160r2 = 17, // deprecated
    secp192k1 = 18, // deprecated
    secp192r1 = 19, // deprecated
    secp224k1 = 20, // deprecated
    secp224r1 = 21, // deprecated
    secp256k1 = 22, // deprecated
    secp256r1 = 23,
    secp384r1 = 24,
    secp521r1 = 25,
    x25519 = 29,
    x448 = 30,
    _,
};