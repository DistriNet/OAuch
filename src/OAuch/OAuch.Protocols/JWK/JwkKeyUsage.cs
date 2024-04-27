using System.Runtime.Serialization;

namespace OAuch.Protocols.JWK {
    public enum JwkKeyUsage {
        [EnumMember(Value = "enc")]
        Encrypt = 1, // enc
        [EnumMember(Value = "sig")]
        Sign = 2 // sig
    }
}
