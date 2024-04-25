using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using OAuch.Protocols.Tls;
using OAuch.Shared;
using OAuch.Shared.Interfaces;
using OAuch.Shared.Logging;

namespace OAuch.Protocols.Http {
    public class HttpHelper {
        public HttpHelper(TestRunContext context) {
            this.State = context.State;
            this.Logger = context.Log;
        }
        private HttpHelper(StateCollection state, LogContext log) {
            this.State = state;
            this.Logger = log;
        }
        /// <summary>
        /// Only use this if we need this class outside of a test run context
        /// </summary>
        public static HttpHelper CreateTransient() {
            return new HttpHelper(new StateCollection(), LogContext.NullLogger);
        }


        private LogContext Logger { get; }
        private StateCollection State { get; }


        //public string GetBasicAuthorizationHeader(string username, string password) {
        //    //username = EncodingHelper.UrlEncode(username);
        //    //password = EncodingHelper.UrlEncode(password);
        //    return $"Basic { EncodingHelper.Base64Encode(username + ":" + password) }";
        //}
        
        public async Task<HttpResponse> SendRequest(HttpRequest req) {
            var mule = new ParameterMule {
                Request = req
            };
            var cookieContainer = new CookieContainer();
            RemoteCertificateValidationCallback certificateCallback = (sender, cert, chain, errors) => {
                mule.IsHttpsUsed = true;
                mule.ServerCertificate = cert != null ? new CertificateReport(cert, errors == SslPolicyErrors.None) : null;
                if (req.ServerCertificateValidationCallback != null)
                    return req.ServerCertificateValidationCallback(sender, cert, chain, errors);
                return true;
            };

            Logger.Log(req);
            // HttpWebRequest.AllowAutoRedirect has a bug where it doesn't set cookies that are returned in a redirect request. So we'll have to implement this manually
            HttpResponse? response = null;
            HttpWebRequest request;
            int tries = req.AllowAutoRedirect ? 10 : 1;
            HttpMethods method = req.Method;
            string url = req.Url;
            byte[] contents = req.Content;
            while (tries > 0) {
                request = await CreateRequest(url, method, cookieContainer, req.ClientCertificates, req.Headers, contents, certificateCallback);
                response = await ReadResponse(request, mule);
                if (!response.StatusCode.IsRedirect())
                    break;
                tries--;
                if (tries > 0 && response.StatusCode.IsRedirect()) {
                    // This is what HttpWebRequest isn't doing 
                    var values = response.Headers.GetValues("Set-Cookie");
                    if (values != null && values.Length > 0) {
                        foreach (var value in values) {
                            var cookie = new Cookie();
                            var components = value.Split(';');
                            var nameValue = components[0].Split('=');
                            if (nameValue.Length == 2) {
                                cookie.Name = nameValue[0].Trim();
                                cookie.Value = nameValue[1].Trim(' ', '\t', '"');
                                for (int ci = 1; ci < components.Length; ci++) {
                                    var comp = components[ci].Trim();
                                    if (comp.StartsWith("Domain=", StringComparison.OrdinalIgnoreCase)) {
                                        cookie.Domain = comp.Substring(7);
                                    }
                                    // There's a bug in CookieContainer if you set the path of a cookie, so just send the cookies to anywhere
                                    //else  if (comp.StartsWith("Path=", StringComparison.OrdinalIgnoreCase)) {
                                    //    cookie.Path = comp.Substring(5);
                                    //}
                                }
                                if (string.IsNullOrEmpty(cookie.Domain)) {
                                    cookie.Domain = request.RequestUri.Host;
                                }
                                try {
                                    cookieContainer.Add(cookie);
                                } catch (Exception e) {
                                    Debug.WriteLine(e.ToString());
                                }
                            }
                        }
                    }

                    //try {
                    //    cookieContainer.SetCookies(request.RequestUri, response.Headers.Get(i));
                    //} catch (Exception e) {
                    //    Debug.WriteLine(e.ToString());
                    //}

                    var location = GetLocation(response, url);
                    if (location == null) {
                        tries = 0; // error; just return what we have
                    } else {
                        url = location;
                        switch (response.StatusCode) {
                            case HttpStatusCode.MovedPermanently:
                            case HttpStatusCode.Found:
                            case HttpStatusCode.SeeOther:
                                method = HttpMethods.Get;
                                contents = new byte[0];
                                break;
                            case HttpStatusCode.TemporaryRedirect:
                            case HttpStatusCode.PermanentRedirect:
                                break;
                            default:
                                tries = 0; // we don't know what the server sent us
                                break;
                        }
                    }
                }
            }
            if (response == null) {
                throw new WebException(); // shouldn't be possible
            }
            Logger.Log(response);
            RegisterSecurityReport(response);
            return response;

            string? GetLocation(HttpResponse response, string originalRequest) {
                var header = response.Headers.Get("Location");
                if (header == null)
                    return null;
                if (!Uri.TryCreate(originalRequest, UriKind.Absolute, out var baseUri) || !Uri.TryCreate(header, UriKind.RelativeOrAbsolute, out var locationUri))
                    return null;
                if (Uri.TryCreate(baseUri, locationUri, out var newUri))
                    return newUri.ToString();
                return null;
            }
            async Task<HttpWebRequest> CreateRequest(string url, HttpMethods method, CookieContainer cookies, X509CertificateCollection certificates, Dictionary<HttpRequestHeaders, string> headers, byte[] content, RemoteCertificateValidationCallback certificateValidation) {
#pragma warning disable SYSLIB0014 // Type or member is obsolete
                var request = WebRequest.Create(url) as HttpWebRequest;
#pragma warning restore SYSLIB0014 // Type or member is obsolete
                if (request == null)
                    throw new NotSupportedException("The specified protocol is not supported; only HTTP(S) is supported.");
                request.Method = method.Name;
                request.CookieContainer = cookies;
                request.ServerCertificateValidationCallback = certificateValidation;
                if (url.IsSecure())
                    request.ClientCertificates = certificates;
                request.AllowAutoRedirect = false;
                foreach (var header in headers) {
                    request.Headers[header.Key.Name] = header.Value;
                }
                if (method == HttpMethods.Post && content.Length > 0) {
                    var requestStream = await request.GetRequestStreamAsync();
                    await requestStream.WriteAsync(content, 0, content.Length);
                }
                return request;
            }

        }
        private async Task<HttpResponse> ReadResponse(WebRequest request, ParameterMule mule) {
            try {
                using (var response = await request.GetResponseAsync()) {
                    return await ReadResponse(response as HttpWebResponse, mule);
                }
            } catch (WebException we) {
                var er = we.Response as HttpWebResponse;
                if (er == null)
                    throw;
                return await ReadResponse(er, mule);
            }
        }
        private async Task<HttpResponse> ReadResponse(HttpWebResponse? response, ParameterMule mule) {
            if (response == null)
                throw new NotSupportedException("The specified protocol is not supported.");
            var responseStream = response.GetResponseStream();
            int capacity = 1024;
            if (response.ContentLength > 0)
                capacity = (int)response.ContentLength;
            var ms = new MemoryStream(capacity);
            mule.NegotiatedTlsVersion = GetTlsVersion(responseStream);
            await responseStream.CopyToAsync(ms);
            mule.Cached = IsCached(response.Headers);
            return new HttpResponse(mule.Request, response.StatusCode, response.Headers, ms.ToArray(), mule);

            SslProtocols? GetTlsVersion(Stream s) {
                try {
                    var bindingFlags = BindingFlags.Instance | BindingFlags.NonPublic;
                    var streamType = s.GetType();
                    var connectionMethod = streamType.GetField("_connection", bindingFlags);
                    if (connectionMethod == null)
                        return null;
                    var connection = connectionMethod.GetValue(s);
                    if (connection == null)
                        return null;
                    var connectionType = connection.GetType();
                    var streamField = connectionType.GetField("_stream", bindingFlags);
                    if (streamField == null)
                        return null;
                    var stream = streamField.GetValue(connection);
                    var sslStream = stream as SslStream;
                    return sslStream?.SslProtocol;
                } catch {
                    return null;
                }
            }
        }
        public static CacheSettings IsCached(WebHeaderCollection headers) {
            var cache = CacheSettings.None;
            if (headers.HasCacheControlNoStore()) cache = cache | CacheSettings.CacheControlNoStore;
            if (headers.HasPragmaNoCache()) cache = cache | CacheSettings.PragmaNoCache;
            return cache;
        }    

        /// <summary>
        /// Registers a full URL
        /// </summary>
        /// <param name="state"></param>
        /// <param name="url"></param>
        public void RegisterUrl(string url) {
            var baseUrl = GetBaseUrl(url);
            if (baseUrl == null)
                return;
            var urlMappings = State.Get<Dictionary<string, string>>(StateKeys.UrlMappings);
            if (!urlMappings.ContainsKey(baseUrl))
                urlMappings[baseUrl] = url;
        }
        public void RegisterSecurityReport(HttpResponse response) {
            var baseUrl = GetBaseUrl(response.Request?.Url);
            if (baseUrl == null)
                return;

            var securityReports = State.Get<Dictionary<string, SecurityReport>>(StateKeys.SecurityReports);
            if (securityReports.ContainsKey(baseUrl))
                return; // we already have a report for this url

            securityReports[baseUrl] = SecurityReport.CreateReportFromResponse(response);
        }
        public static string? GetBaseUrl(string? fullUrl) {
            if (fullUrl == null || !Uri.TryCreate(fullUrl, UriKind.Absolute, out var uri))
                return null;
            return uri.GetComponents(UriComponents.SchemeAndServer | UriComponents.Path, UriFormat.Unescaped);
        }
        public string GetFullUrl(string baseUrl) {
            var urlMappings = State.Get<Dictionary<string, string>>(StateKeys.UrlMappings);
            if (urlMappings.TryGetValue(baseUrl, out var fullUrl)) {
                return fullUrl;
            }
            return baseUrl;
        }
        public async Task<SecurityReport> GetSecurityReport(string url) {
            var securityReports = State.Get<Dictionary<string, SecurityReport>>(StateKeys.SecurityReports);

            var baseUrl = GetBaseUrl(url);
            if (baseUrl == null) 
                throw new ArgumentException("Could not parse url for security report: " + url);
            
            // if we already have a report, use that one
            if (securityReports.TryGetValue(baseUrl, out var storedReport)) {
                return storedReport;
            }

            // we don't have a report yet; let's get it now
            var req = HttpRequest.CreateGet(GetFullUrl(baseUrl));
            req.AllowAutoRedirect = true;
            var resp = await SendRequest(req);
            var newRreport = SecurityReport.CreateReportFromResponse(resp);
            securityReports[baseUrl] = newRreport;
            return newRreport;
        }
        //public string GetFullUrl(string burl) {
        //    var securityReportUrls = State?.Get(_securityReportUrlsKey);
        //    if (securityReportUrls != null && securityReportUrls.TryGetValue(burl, out var full))
        //        return full;
        //    return burl;
        //}
        //public ResponseSecurityReport RegisterSecurityReport(string baseUrl, HttpResponse response) {
        //    var securityReports = State?.Get(_securityReportsKey);
        //    if (securityReports != null && securityReports.TryGetValue(baseUrl, out var res))
        //        return res;
        //    var report = ResponseSecurityReport.CreateReportFromResponse(response);
        //    if (securityReports != null)
        //        securityReports[baseUrl] = report;
        //    return report;
        //}
        //public bool HasSecurityReportFor(string baseUrl) {
        //    var securityReports = State?.Get(_securityReportsKey);
        //    if (securityReports != null && securityReports.TryGetValue(baseUrl, out var res))
        //        return true;
        //    return false;
        //}
        //public void RegisterFullUrl(string baseUrl, string fullUrl) {
        //    if (State == null)
        //        return;
        //    var securityReportUrls = State.Get(_securityReportUrlsKey);
        //    if (!securityReportUrls.ContainsKey(baseUrl))
        //        securityReportUrls[baseUrl] = fullUrl;
        //}

        //private static StateKey<Dictionary<string, ResponseSecurityReport>> _securityReportsKey = new StateKey<Dictionary<string, ResponseSecurityReport>>();
        //private static StateKey<Dictionary<string, string>> _securityReportUrlsKey = new StateKey<Dictionary<string, string>>();

#pragma warning disable SYSLIB0039
#pragma warning disable CS0618
        public async Task<IEnumerable<SslProtocols>> TryDowngradeConnection(string url) {
            // do not cache the result, because it is only used in one test
            if (!Uri.TryCreate(url, UriKind.Absolute ,out var uri))
                return Enumerable.Empty<SslProtocols>();

            var sniffer = new TlsSniffer();
            var options = new SniffOptions() { 
                SniffProtocols = true,
                Protocols = new SslProtocols[] { SslProtocols.Ssl3, SslProtocols.Tls, SslProtocols.Tls11 }
            };
            var result = await sniffer.Sniff(uri, options);
            return result.AcceptedProtocols;
        }
#pragma warning restore SYSLIB0039
#pragma warning restore CS0618

        public async Task<IEnumerable<SslProtocols>> TryModernConnection(string url) {
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
                return Enumerable.Empty<SslProtocols>();
            string host = $"{ uri.Host }:{ uri.Port }";

            var modernReports = State.Get<Dictionary<string, IEnumerable<SslProtocols>>>(StateKeys.ModernConnectionResults);            
            if (modernReports.TryGetValue(host, out var ret))                
                return ret;

            var sniffer = new TlsSniffer();
            var options = new SniffOptions() {
                SniffProtocols = true,
                Protocols = new SslProtocols[] { SslProtocols.Tls12, SslProtocols.Tls13 }
            };
            var result = await sniffer.Sniff(uri, options);
            modernReports[host] = result.AcceptedProtocols;
            return result.AcceptedProtocols;
        }

        internal class ParameterMule : ISecurityReport {
            public bool IsHttpsUsed { get; set; }
            public SslProtocols? NegotiatedTlsVersion { get; set; }
            public CertificateReport? ServerCertificate { get; set; }
            public CacheSettings Cached { get; set; }
            public HttpRequest? Request { get; set; }
            public string? Url => Request?.Url;
        }
    }
}