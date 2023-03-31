using Newtonsoft.Json;
using OAuch.Protocols.JWT;
using OAuch.Shared.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OAuch.LogConverters {
    public class JsonWebTokenConverter : ILogConverter<JsonWebToken> {
        public LoggedItem Convert(JsonWebToken item) {
            return new LoggedJwt() {
                Content = item.ToString(false, Formatting.Indented)
            };
        }
    }
}
