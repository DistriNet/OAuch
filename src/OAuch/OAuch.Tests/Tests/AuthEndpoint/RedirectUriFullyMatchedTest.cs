using OAuch.Compliance.Tests.Features;
using OAuch.Protocols.Http;
using OAuch.Protocols.OAuth2;
using OAuch.Protocols.OAuth2.BuildingBlocks;
using OAuch.Protocols.OAuth2.Pipeline;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using OAuch.Shared.Interfaces;
using System;
using System.Linq;
using System.Threading.Tasks;
using System.Web;

namespace OAuch.Compliance.Tests.AuthEndpoint {
    public class RedirectUriFullyMatchedTest : Test {
        public override string Title => "Does the authorization server exactly match the full redirect uri";
        public override string Description => "This test checks whether the authorization server exactly matches the full redirect uri.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(RedirectUriFullyMatchedTestResult);
    }
    public class RedirectUriFullyMatchedTestResult : TestResult<RedirectUriFullyMatchedTestInfo> {
        public RedirectUriFullyMatchedTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(RedirectUriFullyMatchedTestImplementation);
    }
    public class RedirectUriFullyMatchedTestInfo {
        public RedirectUriMatchedResults? Result { get; set; }
        public bool? WrongRedirect { get; set; }
    }
    public enum RedirectUriMatchedResults {
        UserNotified,
        RequestDenied,
        ParameterIgnored,
        RequestAllowed
    }
    public class RedirectUriFullyMatchedTestImplementation : TestImplementation<RedirectUriFullyMatchedTestInfo> {
        public RedirectUriFullyMatchedTestImplementation(TestRunContext context, RedirectUriFullyMatchedTestResult result, HasSupportedFlowsTestResult flows) : base(context, result, flows) { }

        public async override Task Run() {
            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var modContext = this.Context with {
                SiteSettings = this.Context.SiteSettings with {

                    CallbackUri = this.Context.SiteSettings.CallbackUri?.AddQueryParameter("extra", "oauch")
                }
            };
            var provider = flows.CreateProviderWithStage<SendAuthorizationRedirect, string, ICallbackResult?>(modContext);
            if (provider == null) {
                LogInfo("Could not find a provider that uses the authorization server");
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var redirectResultProcessor = new RedirectFullResultProcessor();
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
        public class RedirectFullResultProcessor : Processor<ICallbackResult?, ICallbackResult?> {
            public bool? WrongRedirect { get; private set; }
            public override Task<ICallbackResult?> Process(ICallbackResult? value, IProvider tokenProvider, TokenResult tokenResult) {
                this.WrongRedirect = null;
                if (value != null) {
                    var uri = new Uri(value.Url);
                    var q = HttpUtility.ParseQueryString(uri.Query);
                    this.WrongRedirect = q.AllKeys.Any(k => k == "extra");
                }
                return Task.FromResult(value);
            }
        }
    }
}