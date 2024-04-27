using OAuch.Shared;
using System.Collections.Generic;

namespace OAuch.Protocols.Tls {
    public class CipherSuite : Enumeration {
        /*
            TLS 1.3
        */
        public static readonly CipherSuite TLS_AES_128_GCM_SHA256 = new(0x1301, nameof(TLS_AES_128_GCM_SHA256), true);
        public static readonly CipherSuite TLS_AES_256_GCM_SHA384 = new(0x1302, nameof(TLS_AES_256_GCM_SHA384), true);
        public static readonly CipherSuite TLS_CHACHA20_POLY1305_SHA256 = new(0x1303, nameof(TLS_CHACHA20_POLY1305_SHA256), true);
        public static readonly CipherSuite TLS_AES_128_CCM_SHA256 = new(0x1304, nameof(TLS_AES_128_CCM_SHA256), true);
        public static readonly CipherSuite TLS_AES_128_CCM_8_SHA256 = new(0x1305, nameof(TLS_AES_128_CCM_8_SHA256), true);

        /*
            Older TLS versions
        */
        public static readonly CipherSuite TLS_RSA_WITH_RC4_128_MD5 = new(0x4, nameof(TLS_RSA_WITH_RC4_128_MD5));
        public static readonly CipherSuite TLS_RSA_WITH_RC4_128_SHA = new(0x5, nameof(TLS_RSA_WITH_RC4_128_SHA));
        public static readonly CipherSuite TLS_RSA_WITH_3DES_EDE_CBC_SHA = new(0xa, nameof(TLS_RSA_WITH_3DES_EDE_CBC_SHA));
        public static readonly CipherSuite TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA = new(0x16, nameof(TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA));
        public static readonly CipherSuite TLS_RSA_WITH_AES_128_CBC_SHA = new(0x2f, nameof(TLS_RSA_WITH_AES_128_CBC_SHA));
        public static readonly CipherSuite TLS_RSA_WITH_AES_256_CBC_SHA = new(0x35, nameof(TLS_RSA_WITH_AES_256_CBC_SHA));
        public static readonly CipherSuite TLS_RSA_WITH_AES_128_CBC_SHA256 = new(0x3c, nameof(TLS_RSA_WITH_AES_128_CBC_SHA256));
        public static readonly CipherSuite TLS_RSA_WITH_AES_256_CBC_SHA256 = new(0x3d, nameof(TLS_RSA_WITH_AES_256_CBC_SHA256));
        public static readonly CipherSuite TLS_RSA_WITH_AES_128_GCM_SHA256 = new(0x9c, nameof(TLS_RSA_WITH_AES_128_GCM_SHA256));
        public static readonly CipherSuite TLS_RSA_WITH_AES_256_GCM_SHA384 = new(0x9d, nameof(TLS_RSA_WITH_AES_256_GCM_SHA384));
        public static readonly CipherSuite TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 = new(0x9e, nameof(TLS_DHE_RSA_WITH_AES_128_GCM_SHA256));
        public static readonly CipherSuite TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 = new(0x9f, nameof(TLS_DHE_RSA_WITH_AES_256_GCM_SHA384));
        public static readonly CipherSuite TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = new(0xc009, nameof(TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA));
        public static readonly CipherSuite TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = new(0xc00a, nameof(TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA));
        public static readonly CipherSuite TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA = new(0xc012, nameof(TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA));
        public static readonly CipherSuite TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = new(0xc013, nameof(TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA));
        public static readonly CipherSuite TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = new(0xc014, nameof(TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA));
        public static readonly CipherSuite TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = new(0xc02b, nameof(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256));
        public static readonly CipherSuite TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = new(0xc02c, nameof(TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384));
        public static readonly CipherSuite TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = new(0xc02f, nameof(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256));
        public static readonly CipherSuite TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = new(0xc030, nameof(TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384));
        public static readonly CipherSuite TLS_PSK_WITH_AES_128_CCM = new(0xc0a4, nameof(TLS_PSK_WITH_AES_128_CCM));
        public static readonly CipherSuite TLS_PSK_WITH_AES_256_CCM = new(0xc0a5, nameof(TLS_PSK_WITH_AES_256_CCM));
        public static readonly CipherSuite TLS_DHE_PSK_WITH_AES_128_CCM = new(0xc0a6, nameof(TLS_DHE_PSK_WITH_AES_128_CCM));
        public static readonly CipherSuite TLS_DHE_PSK_WITH_AES_256_CCM = new(0xc0a7, nameof(TLS_DHE_PSK_WITH_AES_256_CCM));
        public static readonly CipherSuite TLS_PSK_WITH_AES_128_CCM_8 = new(0xc0a8, nameof(TLS_PSK_WITH_AES_128_CCM_8));
        public static readonly CipherSuite TLS_PSK_WITH_AES_256_CCM_8 = new(0xc0a9, nameof(TLS_PSK_WITH_AES_256_CCM_8));
        public static readonly CipherSuite TLS_PSK_DHE_WITH_AES_128_CCM_8 = new(0xc0aa, nameof(TLS_PSK_DHE_WITH_AES_128_CCM_8));
        public static readonly CipherSuite TLS_PSK_DHE_WITH_AES_256_CCM_8 = new(0xc0ab, nameof(TLS_PSK_DHE_WITH_AES_256_CCM_8));
        public static readonly CipherSuite TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = new(0xcca9, nameof(TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256));
        public static readonly CipherSuite TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = new(0xcca8, nameof(TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256));

        public static readonly CipherSuite UNKNOWN = new(0x0, nameof(UNKNOWN));

        private CipherSuite(int id, string name, bool isTls13Cipher = false) : base(id, name) {
            this.IsTls13Cipher = isTls13Cipher;
        }
        public bool IsTls13Cipher { get; }

        public static IEnumerable<CipherSuite> All => [
            TLS_AES_128_GCM_SHA256 ,
            TLS_AES_256_GCM_SHA384 ,
            TLS_CHACHA20_POLY1305_SHA256 ,
            TLS_AES_128_CCM_SHA256 ,
            TLS_AES_128_CCM_8_SHA256,
            TLS_RSA_WITH_RC4_128_MD5,
            TLS_RSA_WITH_RC4_128_SHA,
            TLS_RSA_WITH_3DES_EDE_CBC_SHA ,
            TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA ,
            TLS_RSA_WITH_AES_128_CBC_SHA ,
            TLS_RSA_WITH_AES_256_CBC_SHA ,
            TLS_RSA_WITH_AES_128_CBC_SHA256 ,
            TLS_RSA_WITH_AES_256_CBC_SHA256 ,
            TLS_RSA_WITH_AES_128_GCM_SHA256,
            TLS_RSA_WITH_AES_256_GCM_SHA384 ,
            TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
            TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
            TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
            TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
            TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
            TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            TLS_PSK_WITH_AES_128_CCM,
            TLS_PSK_WITH_AES_256_CCM,
            TLS_DHE_PSK_WITH_AES_128_CCM,
            TLS_DHE_PSK_WITH_AES_256_CCM,
            TLS_PSK_WITH_AES_128_CCM_8,
            TLS_PSK_WITH_AES_256_CCM_8,
            TLS_PSK_DHE_WITH_AES_128_CCM_8,
            TLS_PSK_DHE_WITH_AES_256_CCM_8,
            TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        ];
    }
}