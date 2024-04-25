using System;
using System.Linq;
using System.Collections.Generic;
using System.Net;
using System.Text;
using System.Security.Authentication;
using static OAuch.Protocols.Http.HttpHelper;
using System.IO;
using System.IO.Compression;
using System.Net.Security;

namespace OAuch.Protocols.Http {
    public class HttpResponse {
        private class MyWebHeaderCollection : WebHeaderCollection { // hack
            public void AddHeader(string name, string value) {
                base.AddWithoutValidate(name, value);
            }
        }

        public HttpResponse(Stream responseStream, string origin) {
            this.Origin = origin;

            var securityReport = new ParameterMule();
            var sslStream = responseStream as SslStream;
            if (sslStream != null) {
                securityReport.IsHttpsUsed = true;
                securityReport.NegotiatedTlsVersion = sslStream.SslProtocol;
                if (sslStream.RemoteCertificate != null)
                    securityReport.ServerCertificate = new CertificateReport(sslStream.RemoteCertificate, true);
            }

            // read the headers
            var buffer = new byte[1024 * 1024]; // 1MB should be enough for anyone
            string? rawHead = null;
            var read = responseStream.Read(buffer, 0, buffer.Length);
            var totalRead = 0;
            var headerOffset = -1;
            while (read > 0) {
                totalRead += read;
                headerOffset = FindHeaderOffset(buffer, totalRead);
                if (headerOffset >= 0) {
                    rawHead = Encoding.ASCII.GetString(buffer, 0, headerOffset);
                    break;
                }
                read = responseStream.Read(buffer, totalRead, buffer.Length - totalRead);
            }

            if (rawHead == null)
                throw new InvalidDataException("The received data did not include a HTTP header section.");

            // parse the header and find the content length
            HttpStatusCode statusCode;
            var headers = ParseHeader(rawHead, out statusCode);
            int contentLength;
            if (!int.TryParse(headers[HttpRequestHeader.ContentLength], out contentLength))
                contentLength = -1;

            // download the (rest of) the content
            while (read > 0) {
                var totalBodyRead = totalRead - headerOffset - 4;
                if (contentLength >= 0 && totalBodyRead >= contentLength)
                    break; // we downloaded the full body

                read = responseStream.Read(buffer, totalRead, buffer.Length - totalRead);
                totalRead += read;
            }

            byte[] content = new byte[totalRead - headerOffset - 4];
            Buffer.BlockCopy(buffer, headerOffset + 4, content, 0, content.Length);

            securityReport.Cached = HttpHelper.IsCached(headers);
            Initialize(null, statusCode, headers, content, securityReport);


            // helper functions
            WebHeaderCollection ParseHeader(string rawHead, out HttpStatusCode code) {
                var headers = new MyWebHeaderCollection();
                var lines = rawHead.Split("\r\n");
                var firstline = lines[0].Split(' ');
                code = (HttpStatusCode)int.Parse(firstline[1]);
                for (int i = 1; i < lines.Length; i++) {
                    var colon = lines[i].IndexOf(':');
                    if (colon > 0) {
                        headers.Add(lines[i].Substring(0, colon), lines[i].Substring(colon + 1));
                    }
                }
                return headers;
            }
            int FindHeaderOffset(byte[] buffer, int total) {
                var crlfcrlf = new byte[] { 13, 10, 13, 10 };
                for (int i = 0; i < total; i++) {
                    if (IsMatch(buffer, i, crlfcrlf))
                        return i;
                }
                return -1;
            }
            bool IsMatch(byte[] array, int position, byte[] candidate) {
                if (candidate.Length > (array.Length - position))
                    return false;

                for (int i = 0; i < candidate.Length; i++)
                    if (array[position + i] != candidate[i])
                        return false;

                return true;
            }
        }
        internal HttpResponse(HttpRequest? request, HttpStatusCode statusCode, WebHeaderCollection headers, byte[] content, ISecurityReport securityReport) {
            Initialize(request, statusCode, headers, content, securityReport);
        }
        private void Initialize(HttpRequest? request, HttpStatusCode statusCode, WebHeaderCollection headers, byte[] content, ISecurityReport securityReport) {
            this.Request = request;
            this.StatusCode = statusCode;
            this.Headers = headers;
            this.Content = content;
            this.SecurityReport = securityReport;

            var ce = headers.Get("Content-Encoding"); 
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
        public HttpStatusCode StatusCode { get; private set; }
        public WebHeaderCollection Headers { get; private set; }
        public ISecurityReport SecurityReport { get; private set; }
        public HttpRequest? Request { get; private set; }
        public string? Origin { get; }

        public byte[] Content { get; private set; }
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
