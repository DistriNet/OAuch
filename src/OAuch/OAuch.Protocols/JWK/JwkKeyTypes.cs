using System;
using System.Collections.Generic;
using System.Runtime.Serialization;
using System.Text;

namespace OAuch.Protocols.JWK {
    public enum JwkKeyTypes {
        [EnumMember(Value = "RSA")]
        RSA = 1,
        [EnumMember(Value = "EC")]
        EC = 2,
        [EnumMember(Value = "oct")]
        Oct
    }
}
