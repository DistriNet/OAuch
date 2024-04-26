using System;
using System.Collections.Generic;
using System.Net;
using System.Security.Authentication;
using System.Text;
using System.Web;

namespace OAuch.Protocols.Http {
    public static class Extensions {
        public static bool HasFrameOptions(this WebHeaderCollection headers) {
            return headers.Get("X-Frame-Options") != null;
        }
        public static bool HasCsp(this WebHeaderCollection headers) {
            return headers.Get("Content-Security-Policy") != null;
        }
        public static bool HasPragmaNoCache(this WebHeaderCollection headers) {
            return ((headers.Get("Pragma")?.IndexOf( "no-cache")) ?? -1) >= 0;
        }
        public static bool HasCacheControlNoStore(this WebHeaderCollection headers) {
            return ((headers.Get("Cache-Control")?.IndexOf("no-store")) ?? -1) >= 0;
        }
        public static bool IsSecure(this string url) {
            return url.ToLower().StartsWith("https://");
        }
        public static string ToHttp(this string url) {
            var uriBuilder = new UriBuilder(url) {
                Scheme = Uri.UriSchemeHttp,
                Port = -1 // default port for scheme
            };
            return uriBuilder.ToString();
        }
        public static string AddQueryParameter(this string url, string key, string? value) {
            var uriBuilder = new UriBuilder(url);
            var q = HttpUtility.ParseQueryString(uriBuilder.Query);
            q.Add(key, value);
            uriBuilder.Query = q.ToString();
            return uriBuilder.ToString();
        }
        public static bool IsError(this HttpStatusCode code) {
            var c = (int)code;
            return c >= 400;
        }
        public static bool IsOk(this HttpStatusCode code) {
            var c = (int)code;
            return c >= 200 && c < 300;
        }
        public static bool IsRedirect(this HttpStatusCode code) {
            var c = (int)code;
            return c >= 300 && c < 400;
        }
        public static string GetName(this SslProtocols? protocol) {
            if (protocol == null)
                return "unknown";
            return protocol.Value switch {
                SslProtocols.Ssl3 => "SSL 3.0",
                SslProtocols.Tls => "TLS 1.0",
                SslProtocols.Tls11 => "TLS 1.1",
                SslProtocols.Tls12 => "TLS 1.2",
                SslProtocols.Tls13 => "TLS 1.3",
                _ => "unknown",
            };
        }
    }
}
