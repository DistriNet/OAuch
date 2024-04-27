using OAuch.Protocols.Http;
using OAuch.Shared.Logging;

namespace OAuch.LogConverters {
    public class HttpResponseConverter : ILogConverter<HttpResponse> {
        public LoggedItem Convert(HttpResponse item) {
            return new LoggedHttpResponse() {
                Response = item.ToString(false),
                StatusCode = (int)item.StatusCode,
                Origin = item.Origin
            };
        }
    }
}
