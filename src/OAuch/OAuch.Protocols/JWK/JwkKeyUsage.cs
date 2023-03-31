using System;
using System.Collections.Generic;
using System.Runtime.Serialization;
using System.Text;

namespace OAuch.Protocols.JWK {
    public enum JwkKeyUsage {
        [EnumMember(Value = "enc")]
        Encrypt = 1, // enc
        [EnumMember(Value = "sig")]
        Sign = 2 // sig
    }
}
