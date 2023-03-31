using System;
using System.Linq;
using System.Collections.Generic;
using System.Net;
using System.Text;
using System.Security.Authentication;
using static OAuch.Protocols.Http.HttpHelper;
using System.IO;
using System.IO.Compression;

namespace OAuch.Protocols.Http {
    public class HttpResponse {
        internal HttpResponse(HttpRequest? request, HttpStatusCode statusCode, WebHeaderCollection headers, byte[] content, ISecurityReport securityReport) {
            this.Request = request;
            this.StatusCode = statusCode;
            this.Headers = headers;
            this.Content = content;
            this.SecurityReport = securityReport;

            var ce = headers[HttpResponseHeader.ContentEncoding];
            if (ce != null) {
                Func<Stream, Stream>? decompressor = null;
                switch (ce.ToLower()) {
                    case "gzip":
                        decompressor = s => new GZipStream(s, CompressionMode.Decompress);
                        break;
                    case "deflate":
                        decompressor = s => new DeflateStream(s, CompressionMode.Decompress);
                        break;
                    case "br":
                        decompressor = s => new BrotliStream(s, CompressionMode.Decompress);
                        break;
                }
                if (decompressor != null) {
                    try {
                        var ms = new MemoryStream(content);
                        var decompressStream = decompressor(ms);
                        var resultStream = new MemoryStream();
                        decompressStream.CopyTo(resultStream);
                        this.Content = resultStream.ToArray();
                    } catch { /* leave it compressed */ }
                }
            }
        }
        private HttpResponse(HttpStatusCode code) : this(null, code, new WebHeaderCollection(), new byte[0], new ParameterMule()) { }
        public HttpStatusCode StatusCode { get; }
        public WebHeaderCollection Headers { get; }
        public ISecurityReport SecurityReport { get; }
        public HttpRequest? Request { get; }

        public byte[] Content { get; }
        public override string ToString() {
            return ToString(false);
        }
        public string ToString(bool contentsOnly) {
            var sb = new StringBuilder();
            if (!contentsOnly) {
                sb.AppendLine($"HTTP { (int)StatusCode } { Enum.GetName(typeof(HttpStatusCode), StatusCode) }");
                for(int i = 0; i < Headers.Count; i++) {
                    var key = Headers.GetKey(i);
                    var value = Headers.Get(i);
                    sb.AppendLine($"{ key }: { value }");
                }
                sb.AppendLine();
            }
            if (Content.Length > 0) {
                var encoding = FindEncoding();
                sb.Append(encoding.GetString(Content));
                if (!contentsOnly) {
                    sb.AppendLine();
                }
            }
            return sb.ToString();

            Encoding FindEncoding() {
                var contentType = this.Headers.Get("Content-Type");
                if (contentType != null) {
                    var charset = contentType.Split(';').SingleOrDefault(i => i.TrimStart().StartsWith("charset="));
                    if (charset != null) {
                        int index = charset.IndexOf('=');
                        if (index > 0) {
                            var charsetValue = charset.Substring(index + 1).Trim();
                            switch (charsetValue.ToLower()) {
                                case "utf-8":
                                case "csutf8":
                                    return Encoding.UTF8;
                                case "windows-1252":
                                case "cswindows1252":
                                    return Encoding.GetEncoding(1252);
                                case "us-ascii":
                                case "iso-ir-6":
                                case "ansi_x3.4-1968":
                                case "ansi_x3.4-1986":
                                case "iso_646.irv:1991":
                                case "iso646-us":
                                case "us":
                                case "ibm367":
                                case "cp367":
                                case "csascii":
                                    return Encoding.ASCII;
                                case "utf-16":
                                case "utf-16le":
                                case "csutf16":
                                case "csutf16le":
                                    return Encoding.Unicode;
                                case "utf-16be":
                                case "csutf16be":
                                    return Encoding.BigEndianUnicode;
                                case "utf-32":
                                case "utf-32le":
                                case "csutf32":
                                case "csutf32le":
                                    return Encoding.UTF32;
                                case "utf-7":
                                case "csutf7":
                                    return Encoding.UTF7;
                            }
                            try {
                                var enc = Encoding.GetEncoding(charsetValue);
                                if (enc != null)
                                    return enc;
                            } catch { }
                        }
                    }
                }
                return Encoding.UTF8;
            }
        }

        public static HttpResponse Invalid {
            get {
                return new HttpResponse(HttpStatusCode.InternalServerError);
            }
        }
    }
}
