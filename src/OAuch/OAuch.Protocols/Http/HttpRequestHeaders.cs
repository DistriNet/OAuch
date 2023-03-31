using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using OAuch.Shared;

namespace OAuch.Protocols.Http {
    public class HttpRequestHeaders : Enumeration {
        public static HttpRequestHeaders ContentType = new HttpRequestHeaders(1, "Content-Type");
        public static HttpRequestHeaders Authorization = new HttpRequestHeaders(2, "Authorization");
        public static HttpRequestHeaders ContentLength = new HttpRequestHeaders(3, "Content-Length");
        public static HttpRequestHeaders CacheControl = new HttpRequestHeaders(4, "Cache-Control");
        public static HttpRequestHeaders AcceptEncoding = new HttpRequestHeaders(5, "Accept-Encoding");

        private HttpRequestHeaders(int id, string name) : base(id, name) { }

        static HttpRequestHeaders() {
            _headers = new List<HttpRequestHeaders>();
            _headers.Add(ContentType);
            _headers.Add(Authorization);
            _headers.Add(ContentLength);
            _headers.Add(CacheControl);
            _headers.Add(AcceptEncoding);
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
        private static List<HttpRequestHeaders> _headers;
    }
}
