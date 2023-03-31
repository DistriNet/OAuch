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
    public class IsPkceDowngradeDetectedTest : Test {
        public override string Title => "Is PKCE downgrade detected (authorization request)";
        public override string Description => "Attackers can downgrade PKCE protection without the server noticing. The server should disallow authorization code exchanges where a code_verifier is presented, if there was no code_challenge present in the authorization request.";
        public override string? TestingStrategy => "";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(IsPkceDowngradeDetectedTestResult);
    }
    public class IsPkceDowngradeDetectedTestResult : TestResult {
        public IsPkceDowngradeDetectedTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(IsPkceDowngradeDetectedTestImplementation);
    }
    public class IsPkceDowngradeDetectedTestImplementation : TestImplementation {
        public IsPkceDowngradeDetectedTestImplementation(TestRunContext context, IsPkceDowngradeDetectedTestResult result, HasSupportedFlowsTestResult flows, IsPkceImplementedTestResult implemented) : base(context, result, flows, implemented) { }

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

            var provider = flows.CreateProvider(pkceContext, (fact, prov) => prov.FlowType == OAuthHelper.CODE_FLOW_TYPE);
            if (provider == null) {
                Result.Outcome = TestOutcomes.Skipped;
                LogInfo("The authorization code grant is not working");
                return;
            }

            var processor = new InvalidateVerifier();
            provider.Pipeline.AddAfter<AddPKCEChallenge, Dictionary<string, string?>, Dictionary<string, string?>>(processor);

            var result = await provider.GetToken();
            if (result.AccessToken == null) {
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
                LogInfo("The token server detected the downgrade attack");
            } else {
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                LogInfo("The token server did not notice that the token exchange used PKCE, whereas the authorization request did not.");
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
