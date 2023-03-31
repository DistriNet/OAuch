using OAuch.Protocols.Http;
using OAuch.Shared.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OAuch.LogConverters {
    public class HttpRequestConverter : ILogConverter<HttpRequest> {
        public LoggedItem Convert(HttpRequest item) {
            return new LoggedHttpRequest() {
                Method = item.Method.Name,
                Url = item.Url,
                Request = item.ToString()
            };
        }
    }
}
