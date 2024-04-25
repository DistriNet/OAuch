using System;
using System.Collections.Generic;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace OAuch.Protocols.Http {
    public class HttpRequest {
        private HttpRequest(HttpMethods method, string url) {
            this.Headers = new Dictionary<HttpRequestHeaders, string>();
            //this.Headers[HttpRequestHeaders.AcceptEncoding] = "gzip, deflate, br";
            this.Method = method;
            this.Url = url;
            this.AllowAutoRedirect = false;
            this.ClientCertificates = new X509CertificateCollection();
            _content = new byte[0];
        }
        public string Url { get; set; }
        public HttpMethods Method { get; set; }
        public Dictionary<HttpRequestHeaders, string> Headers { get; }
        public byte[] Content {
            get {
                return _content;
            }
            set {
                _content = value;
                if (value.Length > 0) {
                    Headers[HttpRequestHeaders.ContentLength] = value.Length.ToString();
                } else {
                    Headers.Remove(HttpRequestHeaders.ContentLength);
                }
            }
        }
        private byte[] _content;
        public bool AllowAutoRedirect { get; set; }
        public X509CertificateCollection ClientCertificates { get; set; }
        public RemoteCertificateValidationCallback? ServerCertificateValidationCallback { get; set; }

        public override string ToString() {
            var sb = new StringBuilder();
            sb.AppendLine( $"{ Method } { Url }");
            foreach (var h in Headers) {
                sb.AppendLine($"{ h.Key.Name }: { h.Value }");
            }
            sb.AppendLine();
            if (Content.Length > 0) {
                sb.AppendLine(Encoding.UTF8.GetString(Content));
                sb.AppendLine();
            }
            return sb.ToString();
        }

        public static HttpRequest CreatePost(string url) {
            return new HttpRequest(HttpMethods.Post, url);
        }
        public static HttpRequest CreateGet(string url) {
            return new HttpRequest(HttpMethods.Get, url);
        }        
    }
}
