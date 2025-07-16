using OAuch.Shared;
using System;
using System.Collections.Generic;
using System.Linq;

namespace OAuch.Protocols.Http {
    public class HttpRequestHeaders : Enumeration {
        public static readonly HttpRequestHeaders ContentType = new(1, "Content-Type");
        public static readonly HttpRequestHeaders Authorization = new(2, "Authorization");
        public static readonly HttpRequestHeaders ContentLength = new(3, "Content-Length");
        public static readonly HttpRequestHeaders CacheControl = new(4, "Cache-Control");
        public static readonly HttpRequestHeaders AcceptEncoding = new(5, "Accept-Encoding");
        public static readonly HttpRequestHeaders UserAgent = new(6, "User-Agent");
        public static readonly HttpRequestHeaders DPoP = new(7, "DPoP");

        private HttpRequestHeaders(int id, string name) : base(id, name) { }

        static HttpRequestHeaders() {
            _headers =
            [
                ContentType,
                Authorization,
                ContentLength,
                CacheControl,
                AcceptEncoding,
                UserAgent,
                DPoP,
            ];
        }

        public static HttpRequestHeaders Create(string name) {
            var matched = _headers.FirstOrDefault(h => string.Equals(h.Name, name, StringComparison.OrdinalIgnoreCase));
            if (matched != null)
                return matched;
            var ret = new HttpRequestHeaders(_negativeCounter, name);
            _headers.Add(ret);
            _negativeCounter--; // every custom header should have a unique ID
            return ret;
        }
        private static int _negativeCounter = -1;
        private static readonly List<HttpRequestHeaders> _headers;
    }
}
