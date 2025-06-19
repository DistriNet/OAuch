using OAuch.Compliance.Tests.Features;
using OAuch.Protocols.OAuth2;
using OAuch.Protocols.OAuth2.BuildingBlocks;
using OAuch.Protocols.OAuth2.Pipeline;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using OAuch.Shared.Interfaces;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Web;

namespace OAuch.Compliance.Tests.AuthEndpoint {
    public class RedirectUriConfusionTest : Test {
        public override string Title => "Is the authorization server vulnerable to path confusion";
        public override string Description => "This test checks whether the authorization server is vulnerable to path confusion (cf. https://dl.acm.org/doi/abs/10.1145/3627106.3627140).";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesBadNoGood;
        public override Type ResultType => typeof(RedirectUriConfusionTestResult);
    }
    public class RedirectUriConfusionTestResult : TestResult<ConfusedUriFullyMatchedTestInfo> {
        public RedirectUriConfusionTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(RedirectUriConfusionTestImplementation);
    }
    public class ConfusedUriFullyMatchedTestInfo {
        public bool? WrongRedirect { get; set; }
    }
    public class RedirectUriConfusionTestImplementation : TestImplementation<ConfusedUriFullyMatchedTestInfo> {
        public RedirectUriConfusionTestImplementation(TestRunContext context, RedirectUriConfusionTestResult result, HasSupportedFlowsTestResult flows, RedirectUriPathMatchedTestResult match) : base(context, result, flows, match) { }

        public async override Task Run() {
            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null || string.IsNullOrEmpty(this.Context.SiteSettings.CallbackUri)) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }
            if (HasFailed<RedirectUriPathMatchedTestResult>()) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            string callbackUriBase = new Uri(this.Context.SiteSettings.CallbackUri).GetLeftPart(UriPartial.Path);
            if (callbackUriBase.EndsWith('/'))
                callbackUriBase = callbackUriBase.TrimEnd('/');

            var modifiedCallbacks = new string[] {
                callbackUriBase + "/FAKEPATH",
                callbackUriBase + "%2FFAKEPATH",
                callbackUriBase + "/..%2FFAKEPATH",
                callbackUriBase + "/%2e%2e%2FFAKEPATH",
                callbackUriBase + "/..%252FFAKEPATH",
                callbackUriBase + "/%252e%252e%252FFAKEPATH",

                callbackUriBase + "/FAKEPATH/..",
                callbackUriBase + "%2FFAKEPATH%2F..",
                callbackUriBase + "%2FFAKEPATH%2F%2e%2e",
                callbackUriBase + "%252FFAKEPATH%252F..",
                callbackUriBase + "%252FFAKEPATH%252F%252e%252e",

                callbackUriBase + "/;/../../FAKEPATH",
                callbackUriBase + "/%3B/../../FAKEPATH",
                callbackUriBase + "%3B%2F..%2F..%2FFAKEPATH",
                callbackUriBase + "%3B%2F%2e%2e%2F%2F%2e%2eFAKEPATH",
                callbackUriBase + "%253B%252F..%252F..%252FFAKEPATH",

                callbackUriBase + "%0A%0D/../../FAKEPATH",
                callbackUriBase + "%0A%0D%2F..%2F..%2FFAKEPATH",
                callbackUriBase + "%0A%0D%2F%2e%2e%2F%2F%2e%2eFAKEPATH",
                callbackUriBase + "%250A%250D%252F..%252F..%252FFAKEPATH"
            };

            Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
            int cnt = 1;
            foreach (var c in modifiedCallbacks) {
                var status = await TestCallback(flows, c);
                if (status == TestOutcomes.SpecificationNotImplemented) {
                    LogInfo($"The callback '{c}' triggered a path confusion on the server.");
                    Result.Outcome = status;
                    break;
                }
                await Context.Browser.SendMessage($"Confusion test {cnt}/{modifiedCallbacks.Length} completed.");
                cnt++;
            }
        }
        private async Task<TestOutcomes> TestCallback(HasSupportedFlowsTestResult flows, string callback) {
            var modContext = this.Context with {
                SiteSettings = this.Context.SiteSettings with {
                    CallbackUri = callback
                }
            };
            var provider = flows.CreateProviderWithStage<SendAuthorizationRedirect, string, ICallbackResult?>(modContext);
            if (provider == null) {
                LogInfo("Could not find a provider that uses the authorization server");
                return TestOutcomes.Skipped;
            }

            var redirectResultProcessor = new ConfusedPathResultProcessor();
            provider.Pipeline.AddAfter<SendAuthorizationRedirect, string, ICallbackResult?>(redirectResultProcessor);
            var unescapedRedirect = new UnescapedRedirectProcessor();
            provider.Pipeline.Replace<BuildAuthorizationUrl, Dictionary<string, string?>, string>(unescapedRedirect);

            await provider.GetToken();
            ExtraInfo.WrongRedirect = redirectResultProcessor.WrongRedirect;
            if (ExtraInfo.WrongRedirect == true)
                return TestOutcomes.SpecificationNotImplemented;
            return TestOutcomes.SpecificationFullyImplemented;
        }

        public class ConfusedPathResultProcessor : Processor<ICallbackResult?, ICallbackResult?> {
            public ConfusedPathResultProcessor() { }
            public bool? WrongRedirect { get; private set; }
            public override Task<ICallbackResult?> Process(ICallbackResult? value, IProvider tokenProvider, TokenResult tokenResult) {
                this.WrongRedirect = null;
                if (value != null) {
                    this.WrongRedirect = value.Url.Contains("FAKEPATH");
                }
                return Task.FromResult(value);
            }
        }
        public class UnescapedRedirectProcessor : Processor<Dictionary<string, string?>, string> {
            // this processor makes sure that redirect_uri isn't encoded;
            // we need to use the redirect_uri precisely like it is specified (as it is specifically
            // constructed to confuse parsers)
            public override Task<string?> Process(Dictionary<string, string?> value, IProvider tokenProvider, TokenResult tokenResult) {
                var uriBuilder = new UriBuilder(tokenProvider.SiteSettings.AuthorizationUri!);
                var query = HttpUtility.ParseQueryString(uriBuilder.Query);
                value.Remove("redirect_uri");
                foreach (var key in value.Keys) {
                    var s = value[key];
                    if (!string.IsNullOrEmpty(s))
                        query[key] = s;
                }
                uriBuilder.Query = (value.Count > 0 ? (query.ToString() + "&") : "") + "redirect_uri=" + tokenProvider.SiteSettings.CallbackUri;
                return Task.FromResult<string?>(uriBuilder.ToString());
            }
        }
    }
}