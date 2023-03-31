using OAuch.Protocols.Http;
using OAuch.Shared.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OAuch.LogConverters {
    public class HttpResponseConverter : ILogConverter<HttpResponse> {
        public LoggedItem Convert(HttpResponse item) {
            return new LoggedHttpResponse() {
                 Response = item.ToString(false),
                 StatusCode = (int)item.StatusCode
            };
        }
    }
}
