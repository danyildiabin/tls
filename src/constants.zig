pub const Record = struct {
    type: ContentType,
    version: Version,
    data: []u8,
};

pub const Client = struct {
    cipher: u16,
    session_id: Version,
    compression: []u8,

};

// Formated as IANA names
// PROTOCOL KEY_EXCHANGE_ALGORITHM DIGITAL_SIGNATURE_ALGORITHM BULK_ENCRYPTION_ALGORITHM HASHING_ALGORITHM
// List defined here are approved TLS 1.2 Ciphers according to
// https://comodosslstore.com/resources/ssl-cipher-suites-ultimate-guide/
// kinda cringe, I know

// ECDHE - Elliptic Curve Diffie-Hellman Ephemeral
// ECDSA - Elliptic Curve Digital Signature Algorithm
// GCM - Galois/Counter mode
// AES - Advanced encryption standard 
// SHA - Secure Hash Algorithm
// CBC - Cipher Block Chaining
// RSA - Rivest Shamir Adleman algorithm
pub const CipherSuite = enum (u16) {
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xC02B,       // Recommended
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xC02C,       // Recommended
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = 0xC023,       // Weak
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = 0xC024,       // Weak
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xC02F,         // Secure
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xC030,         // Secure
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 = 0xC027,         // Weak
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 = 0xC028,         // Weak
    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 = 0x009E,           // Secure
    TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 = 0x009F,           // Secure
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA = 0x0033,              // Weak
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA = 0x0039,              // Weak
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = 0x0067,           // Weak
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 = 0x006B,           // Weak
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCA9, // Recommended
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCA8,   // Secure
    _,
};

pub const ContentType = enum (u8) {
    invalid = 0,
    change_cipher_spec = 20,
    alert = 21,
    handshake = 22,
    application_data = 23,
    heartbeat = 24,
    _,
};

pub const AlertLevel = enum (u8) {
    warning = 1,
    fatal = 2,
    _,
};
 
pub const AlertDescription = enum (u8) {
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

pub const HandshakeType = enum (u8) {
    hello_request = 0,
    client_hello = 1,
    server_hello = 2,
    new_session_ticket = 4,
    end_of_early_data = 5,
    encrypted_extensions = 8,
    certificate = 11,
    server_key_exchange  = 12,
    certificate_request = 13,
    server_hello_done = 14,
    certificate_verify = 15,
    client_key_exchange = 16,
    finished = 20,
    certificate_status = 22,
    key_update = 24,
    message_hash = 254,
    _,
};

pub const Version = enum (u16) {
    SSL_3_0 = 0x0300,
    TLS_1_0 = 0x0301,
    TLS_1_1 = 0x0302,
    TLS_1_2 = 0x0303,
    TLS_1_3 = 0x0304,
    _,
};