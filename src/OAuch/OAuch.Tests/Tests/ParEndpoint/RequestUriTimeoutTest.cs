using AngleSharp.Dom;
using OAuch.Compliance.Tests.Features;
using OAuch.Compliance.Tests.Shared;
using OAuch.Protocols.OAuth2;
using OAuch.Protocols.OAuth2.BuildingBlocks;
using OAuch.Protocols.OAuth2.Pipeline;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.ParEndpoint {
    public class RequestUriTimeoutTest : Test {
        public override string Title => "Does the request_uri time out";
        public override string Description => "This test checks whether the generated request_uri times out.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(RequestUriTimeoutTestResult);
    }
    public class RequestUriTimeoutTestResult : TestResult<RequestUriTimeoutInfo> {
        public RequestUriTimeoutTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(RequestUriTimeoutTestImplementation);
    }
    public class RequestUriTimeoutInfo : ITimeDelayedTest {
        public string? RequestUri { get; set; }
        public DateTime? ResumeWhen { get; set; }
    }
    public class RequestUriTimeoutTestImplementation : TestImplementation<RequestUriTimeoutInfo> {
        public RequestUriTimeoutTestImplementation(TestRunContext context, RequestUriTimeoutTestResult result, HasSupportedFlowsTestResult flows, IsParSupportedTestResult par) : base(context, result, flows, par) { }

        public async override Task Run() {
            if (HasFailed<IsParSupportedTestResult>()) { // no PAR support
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var prov = flows.CreateProviderWithStage<PushAuthorizationRequest, Dictionary<string, string?>, Dictionary<string, string?>>(Context);
            if (prov == null) {
                Result.Outcome = TestOutcomes.Skipped; // no providers that support the PAR standard (weird, should not happen here, because we know PAR is supported)
                return;
            }

            if (ExtraInfo.RequestUri == null) {
                // request the URI
                prov.Pipeline.AddAfter<PushAuthorizationRequest, Dictionary<string, string?>, Dictionary<string, string?>>(new CancelRequest());

                var token = await prov.GetToken();
                if (token.ParRequestUri == null) {
                    LogInfo("Could not retrieve request_uri.");
                    Result.Outcome = TestOutcomes.Skipped;
                } else {
                    ExtraInfo.RequestUri = token.ParRequestUri;
                    if (token.ParRequestUriTimeout == null || token.ParRequestUriTimeout <= 0)
                        token.ParRequestUriTimeout = 600; // taken from section 2.2 in RFC9126; this is not a hard requirement
                    ExtraInfo.ResumeWhen = DateTime.Now.AddSeconds(token.ParRequestUriTimeout.Value);
                    LogInfo($"request_uri succesfully retrieved. Please resume this test run after {ExtraInfo.ResumeWhen.Value:HH:mm:ss} to complete the test.");
                }
            } else if (DateTime.Now > ExtraInfo.ResumeWhen!.Value) {
                prov.Pipeline.Replace<PushAuthorizationRequest, Dictionary<string, string?>, Dictionary<string, string?>>(new OverrideRequestUri(ExtraInfo.RequestUri));

                var token = await prov.GetToken();
                if (token.AccessToken == null && token.IdentityToken == null) {
                    Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
                    LogInfo("The request_uri timed out");
                } else {
                    Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                    LogInfo("The request_uri was still valid after the timeout");
                }
            }
        }
        class CancelRequest : Processor<Dictionary<string, string?>, Dictionary<string, string?>> {
            public override Task<Dictionary<string, string?>?> Process(Dictionary<string, string?> value, IProvider provider, TokenResult tokenResult) {
                this.Succeeded = false; // cancel
                return Task.FromResult(value);
            }
        }
        class OverrideRequestUri : Processor<Dictionary<string, string?>, Dictionary<string, string?>> {
            public OverrideRequestUri(string uri) {
                this.Uri = uri;
            }
            public string Uri { get; }
            public override Task<Dictionary<string, string?>?> Process(Dictionary<string, string?> value, IProvider provider, TokenResult tokenResult) {
                value.Clear();
                value["client_id"] = provider.SiteSettings.DefaultClient.ClientId;
                value["request_uri"] = this.Uri;
                return Task.FromResult(value);
            }
        }
    }
}
