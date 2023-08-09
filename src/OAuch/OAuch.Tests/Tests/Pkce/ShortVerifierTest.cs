using OAuch.Compliance.Tests.Features;
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

namespace OAuch.Compliance.Tests.Pkce {
    public class ShortVerifierTest : Test {
        public override string Title => "Are insecure code verifiers rejected";
        public override string Description => "This test checks whether the server rejects PKCE code verifiers that are too short (less than 34 characters).";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(ShortVerifierTestResult);
    }
    public class ShortVerifierTestResult : TestResult {
        public ShortVerifierTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(ShortVerifierTestImplementation);
    }
    public class ShortVerifierTestImplementation : TestImplementation {
        public ShortVerifierTestImplementation(TestRunContext context, ShortVerifierTestResult result, HasSupportedFlowsTestResult flows, IsPkceImplementedTestResult implemented) : base(context, result, flows, implemented) { }

        public async override Task Run() {
            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null || HasFailed<IsPkceImplementedTestResult>()) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var workingPkceTypes = Context.State.Get<List<PKCESupportTypes>>(StateKeys.WorkingPkceTypes);
            PKCESupportTypes selectedPkceType;
            if (workingPkceTypes.Contains(PKCESupportTypes.Hash)) {
                selectedPkceType = PKCESupportTypes.Hash;
            } else if (workingPkceTypes.Contains(PKCESupportTypes.Plain)) {
                selectedPkceType = PKCESupportTypes.Plain;
            } else { // only none is working
                LogInfo("PKCE is not allowed on the server");
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                return;
            }

            var pkceContext = this.Context with
            {
                SiteSettings = this.Context.SiteSettings with
                {
                    PKCEDefault = selectedPkceType
                }
            };

            var provider = flows.CreateProvider(pkceContext, (fact, prov) => prov.FlowType == OAuthHelper.CODE_FLOW_TYPE) as AuthorizationCodeTokenProvider;
            if (provider == null) {
                Result.Outcome = TestOutcomes.Skipped;
                LogInfo("The authorization code grant is not working");
                return;
            }

            provider.CodeVerifier = "abc";
            var result = await provider.GetToken();
            if (result.AccessToken == null) {
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
                LogInfo("The token server did not accept a short verifier");
            } else {
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                LogInfo("The token server accepted the short code verifier 'abc'.");
            }
        }
        public class InvalidateVerifier : Processor<Dictionary<string, string?>, Dictionary<string, string?>> {
            public override Task<Dictionary<string, string?>?> Process(Dictionary<string, string?> value, IProvider tokenProvider, TokenResult tokenResult) {
                value.Remove("code_challenge");
                value.Remove("code_challenge_method");
                return Task.FromResult<Dictionary<string, string?>?>(value);
            }
        }
    }
}
