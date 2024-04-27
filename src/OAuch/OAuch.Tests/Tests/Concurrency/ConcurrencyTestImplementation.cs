using OAuch.Compliance.Tests.Features;
using OAuch.Protocols.Http;
using OAuch.Protocols.OAuth2;
using OAuch.Protocols.OAuth2.Pipeline;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.Concurrency {
    public abstract class ConcurrencyTestImplementation : TestImplementation<ConcurrencyInfo> {
        public ConcurrencyTestImplementation(TestRunContext context, TestResult<ConcurrencyInfo> result, HasSupportedFlowsTestResult flows, TestUriSupportedTestResult testUri) : base(context, result, flows, testUri) {
            //
        }
        // resolve the addresses of the token server
        public abstract IReadOnlyList<ServerInfo>? ResolveAddresses();

        protected async Task RunInternal(TokenProvider provider, TokenResult baseToken, PipelineStage<HttpRequest> pipeline) {
            var exchangeResponses = await TestConcurrentRequests(provider, baseToken, pipeline);
            if (exchangeResponses == null) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }
            var succeededRequests = exchangeResponses.Where(r => (int)r.ResponseCode >= 200 && (int)r.ResponseCode < 300).ToList();

            this.ExtraInfo.SucceededRequestCount = succeededRequests.Count;
            this.ExtraInfo.TotalRequestCount = exchangeResponses.Count();
            this.ExtraInfo.ReturnedAccessTokens = succeededRequests.Where(r => r.AccessToken != null).Select(r => r.AccessToken!).Distinct().ToList();
            this.ExtraInfo.ReturnedRefreshTokens = succeededRequests.Where(r => r.RefreshToken != null).Select(r => r.RefreshToken!).Distinct().ToList();

            LogInfo($"{this.ExtraInfo.SucceededRequestCount} out of {this.ExtraInfo.TotalRequestCount} requests succeeded");
            LogInfo($"Received {this.ExtraInfo.ReturnedAccessTokens?.Count ?? 0} new unique access token(s) and {this.ExtraInfo.ReturnedRefreshTokens?.Count ?? 0} new unique refresh token(s)");

            // test the access tokens
            this.ExtraInfo.WorkingAccessTokens = [];
            if (this.ExtraInfo.ReturnedAccessTokens != null) {
                var api = GetDependency<TestUriSupportedTestResult>(true);
                if (api == null) {
                    LogInfo("Cannot test the validity of the access tokens (no API endpoint)");
                } else {
                    foreach (var at in this.ExtraInfo.ReturnedAccessTokens) {
                        if (at != null) {
                            if (await TokenTestHelper.TestAccessToken(Context, at))
                                this.ExtraInfo.WorkingAccessTokens.Add(at);
                        }
                    }
                    this.ExtraInfo.AccessTokensValidCount = this.ExtraInfo.WorkingAccessTokens.Count;
                    LogInfo($"{this.ExtraInfo.AccessTokensValidCount} out of {this.ExtraInfo.ReturnedAccessTokens.Count} access tokens worked");
                }
            }

            //// test the refresh tokens
            this.ExtraInfo.WorkingRefreshTokens = [];
            if (this.ExtraInfo.ReturnedRefreshTokens != null) {
                foreach (var rt in this.ExtraInfo.ReturnedRefreshTokens) {
                    if (rt != null) {
                        var (working, newRefresh) = await TokenTestHelper.TestRefreshToken(rt, provider);
                        if (working) {
                            this.ExtraInfo.WorkingRefreshTokens.Add(newRefresh ?? rt);
                        }
                    }
                }
                this.ExtraInfo.RefreshTokensValidCount = this.ExtraInfo.WorkingRefreshTokens.Count;
                LogInfo($"{this.ExtraInfo.RefreshTokensValidCount} out of {this.ExtraInfo.ReturnedRefreshTokens.Count} refresh tokens worked");
            }

            if (this.ExtraInfo.ReturnedAccessTokens!.Count == 1 && this.ExtraInfo.ReturnedRefreshTokens!.Count <= 1) {
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
            } else {
                Result.Outcome = this.ExtraInfo.AccessTokensValidCount > 1 || this.ExtraInfo.RefreshTokensValidCount > 1 ? TestOutcomes.SpecificationNotImplemented : TestOutcomes.SpecificationPartiallyImplemented;
            }
        }

        //protected void Sleep(int milliseconds) {
        //    Stopwatch stopwatch = new Stopwatch();
        //    stopwatch.Start();

        //    while (stopwatch.ElapsedMilliseconds < milliseconds) {
        //        var timeout = milliseconds - (int)stopwatch.ElapsedMilliseconds;
        //        Thread.Sleep(timeout >= 0 ? timeout : 0);
        //    }

        //    stopwatch.Stop();
        //}
        public async Task<IEnumerable<HttpServerResponse>?> TestConcurrentRequests(TokenProvider provider, TokenResult baseToken, PipelineStage<HttpRequest> pipeline) {
            await pipeline.Run(provider, baseToken);
            if (pipeline.Result == null) {
                LogInfo("Could not create the request.");
                return null;
            }

            var servers = ResolveAddresses();
            if (servers == null || servers.Count == 0) {
                LogInfo("Could not resolve enough addresses for the token server.");
                return null;
            }

            var request = pipeline.Result;
            var results = new List<HttpServerResponse>();
            var threads = new List<Thread>();
            var parameterList = new List<RequestThreadParameters>();
            for (int i = 0; i < servers.Count; i++) { // start running all threads
                var parameters = new RequestThreadParameters(results, new ManualResetEventSlim(false), request, servers[i], new ManualResetEventSlim(false));
                parameterList.Add(parameters);
                var t = new Thread(RequestStart);
                t.Start(parameters);
                threads.Add(t);
            }
            foreach (var pe in parameterList) { // wait until the TLS negotiation has completed
                pe.ReadyHandle.Wait();
            }

            var sortedList = parameterList.OrderBy(c => c.Server.TripTime).ToList();

            if (DISABLE_SERVER_TIME_OFFSETS) {
                // remove the timing information by setting the TripTime to 0 for every server
                sortedList = sortedList.Select(el => new RequestThreadParameters(el.Results, el.BlockHandle, el.Request, new ServerInfo(el.Server.Ip), el.ReadyHandle)).ToList();
            }

            var start = PreciseTime.Now;
            int pointer = 0;
            while (pointer < sortedList.Count) {
                var elapsedMs = (int)PreciseTime.Now.Subtract(start).TotalMilliseconds;
                while (pointer < sortedList.Count && sortedList[pointer].Server.TripTime <= elapsedMs) {
                    System.Diagnostics.Debug.WriteLine($"Released {sortedList[pointer].Server.Ip} after {elapsedMs}ms");
                    sortedList[pointer].BlockHandle.Set();
                    pointer++;
                }
            }

            foreach (var t in threads) {
                t.Join();
            }
            return results;
        }

        protected void RequestStart(object? obj) {
            var parameters = obj as RequestThreadParameters;
            if (parameters == null)
                return;
            var request = parameters.Request;
            var ip = parameters.Server.Ip;

            try {
                var uri = new Uri(request.Url);
                using var client = new TcpClient();
                client.Connect(ip, uri.Port);

                Stream networkStream = client.GetStream();
                if (uri.Port != 80) { // we use HTTPS by default
                    var sslStream = new SslStream(networkStream, false, ServerCertificateValidator);
                    sslStream.AuthenticateAsClient(uri.Host);
                    networkStream = sslStream;
                }

                // build query
                var header = new StringBuilder();
                header.AppendLine($"{request.Method.Name} {uri.PathAndQuery} HTTP/1.0");
                header.AppendLine($"Host: {uri.Host}");
                foreach (var headerEntry in request.Headers) {
                    header.AppendLine($"{headerEntry.Key.Name}: {headerEntry.Value}");
                }
                if (request.Content != null && request.Content.Length > 0 && !request.Headers.Any(c => c.Key.Name == "Content-Length")) {
                    header.AppendLine($"Content-Length: {request.Content.Length}");
                }
                header.AppendLine();
                var headerBytes = Encoding.UTF8.GetBytes(header.ToString());

                // send bytes
                networkStream.Write(headerBytes, 0, headerBytes.Length);

                // signal we're ready to send the Content
                parameters.ReadyHandle.Set();

                // wait until everything is ready
                parameters.BlockHandle.Wait();

                // send the content
                if (request.Content != null && request.Content.Length > 0) {
                    networkStream.Write(request.Content, 0, request.Content.Length);
                    networkStream.Flush();
                }

                var httpResponse = new HttpResponse(networkStream, ip.ToString());
                Log(httpResponse);
                var serverResponse = ServerResponse.FromResponseBody(httpResponse);
                lock (parameters.Results) {
                    parameters.Results.Add(serverResponse);
                }
            } catch (Exception e) {
                parameters.ReadyHandle.Set();
                System.Diagnostics.Debug.WriteLine(e.ToString());
            }
        }
        protected record RequestThreadParameters(List<HttpServerResponse> Results, ManualResetEventSlim BlockHandle, HttpRequest Request, ServerInfo Server, ManualResetEventSlim ReadyHandle) { }
        protected static bool ServerCertificateValidator(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors) => true;

        private const bool DISABLE_SERVER_TIME_OFFSETS = true;
    }
}
