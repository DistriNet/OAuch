using OAuch.Compliance.Tests.Features;
using OAuch.Protocols.Http;
using OAuch.Protocols.OAuth2;
using OAuch.Protocols.OAuth2.BuildingBlocks;
using OAuch.Protocols.OAuth2.Pipeline;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using OAuch.Shared.Interfaces;
using System;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.AuthEndpoint {
    public class CodePollutionTest : Test {
        public override string Title => "Can the authorization code be polluted";
        public override string Description => "This test checks whether the authorization code can be polluted using a parameter pollution attack (cf. https://dl.acm.org/doi/abs/10.1145/3627106.3627140).";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesBadNoGood;
        public override Type ResultType => typeof(CodePollutionTestResult);
    }
    public class CodePollutionTestResult : TestResult<CodePollutionTestInfo> {
        public CodePollutionTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(CodePollutionTestImplementation);
    }
    public class CodePollutionTestInfo {
        public bool? IsCodePolluted { get; set; }
    }
    public class CodePollutionTestImplementation : TestImplementation<CodePollutionTestInfo> {
        public CodePollutionTestImplementation(TestRunContext context, CodePollutionTestResult result, HasSupportedFlowsTestResult flows, RedirectUriFullyMatchedTestResult matched) : base(context, result, flows, matched) { }

        public async override Task Run() {
            if (!HasFailed<RedirectUriFullyMatchedTestResult>()) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var modContext = this.Context with {
                SiteSettings = this.Context.SiteSettings with {
                    CallbackUri = this.Context.SiteSettings.CallbackUri?.AddQueryParameter("code", "attackercode")
                }
            };
            var provider = flows.CreateProviderWithStage<SendAuthorizationRedirect, string, ICallbackResult?>(modContext, mustHaveCodes: true);
            if (provider == null) {
                LogInfo("Could not find a provider that uses the authorization server");
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var redirectResultProcessor = new RedirectFullResultProcessor();
            provider.Pipeline.AddAfter<SendAuthorizationRedirect, string, ICallbackResult?>(redirectResultProcessor);

            await provider.GetToken();
            ExtraInfo.IsCodePolluted = redirectResultProcessor.IsCodePolluted;
            if (redirectResultProcessor.IsCodePolluted == true) {
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
            } else {
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
            }
        }
        public class RedirectFullResultProcessor : Processor<ICallbackResult?, ICallbackResult?> {
            public bool? IsCodePolluted { get; private set; }
            public override Task<ICallbackResult?> Process(ICallbackResult? value, IProvider tokenProvider, TokenResult tokenResult) {
                this.IsCodePolluted = null;
                if (value != null) {
                    this.IsCodePolluted = value.Url.Contains("attackercode");
                }
                return Task.FromResult(value);
            }
        }
    }
}