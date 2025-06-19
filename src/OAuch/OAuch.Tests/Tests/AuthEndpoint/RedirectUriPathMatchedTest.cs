using OAuch.Compliance.Tests.Features;
using OAuch.Protocols.OAuth2;
using OAuch.Protocols.OAuth2.BuildingBlocks;
using OAuch.Protocols.OAuth2.Pipeline;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using OAuch.Shared.Interfaces;
using System;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.AuthEndpoint {
    public class RedirectUriPathMatchedTest : Test {
        public override string Title => "Does the authorization server exactly match the hostname and path of the redirect uri";
        public override string Description => "This test checks whether the authorization server exactly matches the hostname and path of the redirect uri.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(RedirectUriPathMatchedTestResult);
    }
    public class RedirectUriPathMatchedTestResult : TestResult<RedirectUriFullyMatchedTestInfo> {
        public RedirectUriPathMatchedTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(RedirectUriPathMatchedTestImplementation);
    }
    public class RedirectUriPathMatchedTestImplementation : TestImplementation<RedirectUriFullyMatchedTestInfo> {
        public RedirectUriPathMatchedTestImplementation(TestRunContext context, RedirectUriPathMatchedTestResult result, HasSupportedFlowsTestResult flows) : base(context, result, flows) { }

        public async override Task Run() {
            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null || string.IsNullOrEmpty(this.Context.SiteSettings.CallbackUri)) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            string callbackUriBase = new Uri(this.Context.SiteSettings.CallbackUri).GetLeftPart(UriPartial.Path);
            if (callbackUriBase.EndsWith('/'))
                callbackUriBase = callbackUriBase.TrimEnd('/');
            callbackUriBase += "/Wrong";

            var modContext = this.Context with {
                SiteSettings = this.Context.SiteSettings with {
                    CallbackUri = callbackUriBase
                }
            };
            var provider = flows.CreateProviderWithStage<SendAuthorizationRedirect, string, ICallbackResult?>(modContext);
            if (provider == null) {
                LogInfo("Could not find a provider that uses the authorization server");
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var redirectResultProcessor = new RedirectPathResultProcessor(this.Context.SiteSettings.CallbackUri);
            provider.Pipeline.AddAfter<SendAuthorizationRedirect, string, ICallbackResult?>(redirectResultProcessor);

            var result = await provider.GetToken();
            ExtraInfo.WrongRedirect = redirectResultProcessor.WrongRedirect;
            if (redirectResultProcessor.WrongRedirect == null) {
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented; // user clicked 'stalled test'
                ExtraInfo.Result = RedirectUriMatchedResults.UserNotified;
            } else if (result.AccessToken == null) {
                LogInfo("The authorization server denied the request");
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
                ExtraInfo.Result = RedirectUriMatchedResults.RequestDenied;
            } else if (redirectResultProcessor.WrongRedirect == false) {
                LogInfo("The authorization server ignored the extra parameter");
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
                ExtraInfo.Result = RedirectUriMatchedResults.ParameterIgnored;
            } else {
                LogInfo("The authorization server included the extra parameter");
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                ExtraInfo.Result = RedirectUriMatchedResults.RequestAllowed;
            }
        }
        public class RedirectPathResultProcessor : Processor<ICallbackResult?, ICallbackResult?> {
            public RedirectPathResultProcessor(string originalCallback) {
                this.OriginalCallback = originalCallback;
            }
            public bool? WrongRedirect { get; private set; }
            public string OriginalCallback { get; private set; }
            public override Task<ICallbackResult?> Process(ICallbackResult? value, IProvider tokenProvider, TokenResult tokenResult) {
                this.WrongRedirect = null;
                if (value != null && Uri.TryCreate(this.OriginalCallback, UriKind.Absolute, out var settingsUri)) {
                    var uri = new Uri(value.Url);
                    this.WrongRedirect = Uri.Compare(uri, settingsUri, UriComponents.SchemeAndServer | UriComponents.Path, UriFormat.Unescaped, StringComparison.OrdinalIgnoreCase) != 0;
                }
                return Task.FromResult(value);
            }
        }
    }
}