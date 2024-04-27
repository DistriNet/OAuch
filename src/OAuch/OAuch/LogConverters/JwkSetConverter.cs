using Newtonsoft.Json;
using OAuch.Protocols.JWK;
using OAuch.Shared.Logging;

namespace OAuch.LogConverters {
    public class JwkSetConverter : ILogConverter<JwkSet> {
        public LoggedItem Convert(JwkSet item) {
            return new LoggedJwks() {
                Content = item.ToString(Formatting.Indented)
            };
        }
    }
}
