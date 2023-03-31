using Newtonsoft.Json;
using OAuch.Protocols.JWK;
using OAuch.Shared.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OAuch.LogConverters {
    public class JwkSetConverter : ILogConverter<JwkSet> {
        public LoggedItem Convert(JwkSet item) {
            return new LoggedJwks() {
                Content = item.ToString(Formatting.Indented)
            };
        }
    }
}
