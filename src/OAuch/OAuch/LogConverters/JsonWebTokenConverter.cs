using Newtonsoft.Json;
using OAuch.Protocols.JWT;
using OAuch.Shared.Logging;

namespace OAuch.LogConverters {
    public class JsonWebTokenConverter : ILogConverter<JsonWebToken> {
        public LoggedItem Convert(JsonWebToken item) {
            return new LoggedJwt() {
                Content = item.ToString(false, Formatting.Indented)
            };
        }
    }
}
