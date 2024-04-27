using System.Security.Cryptography;

namespace OAuch.Protocols.JWT {
    public abstract class TokenKey {
        public static TokenKey FromBytes(byte[] value) => new BytesTokenKey(value);
        public static TokenKey FromRsa(RSA value) => new RsaTokenKey(value);
        public static TokenKey FromECDsa(ECDsa value) => new ECDsaTokenKey(value);
        public static TokenKey Empty => new EmptyTokenKey();
    }
    public class BytesTokenKey : TokenKey {
        public BytesTokenKey(byte[] value) {
            this.Value = value;
        }
        public byte[] Value { get; }
    }
    public class EmptyTokenKey : TokenKey {
        //
    }
    public class RsaTokenKey : TokenKey {
        public RsaTokenKey(RSA value) {
            this.Value = value;
        }
        public RSA Value { get; }
    }
    public class ECDsaTokenKey : TokenKey {
        public ECDsaTokenKey(ECDsa value) {
            this.Value = value;
        }
        public ECDsa Value { get; }
    }
}
