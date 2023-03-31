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
    public class IsPkcePlainDowngradeDetectedTest : Test {
        public override string Title => "Is PKCE downgrade detected (token request)";
        public override string Description => "Attackers can downgrade PKCE protection without the server noticing. The authorization request used S256 PKCE, but an attacker can downgrade this to plain PKCE by modifying the token request.";
        public override string? TestingStrategy => "";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(IsPkcePlainDowngradeDetectedTestResult);
    }
    public class IsPkcePlainDowngradeDetectedTestResult : TestResult {
        public IsPkcePlainDowngradeDetectedTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(IsPkcePlainDowngradeDetectedTestImplementation);
    }
    public class IsPkcePlainDowngradeDetectedTestImplementation : TestImplementation {
        public IsPkcePlainDowngradeDetectedTestImplementation(TestRunContext context, IsPkcePlainDowngradeDetectedTestResult result, HasSupportedFlowsTestResult flows, IsPkceImplementedTestResult implemented) : base(context, result, flows, implemented) { }

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
            } else { // only plain or none is working
                LogInfo("Hashed PKCE is not supported on the server");
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var pkceContext = this.Context with {
                SiteSettings = this.Context.SiteSettings with {
                    PKCEDefault = selectedPkceType
                }
            };

            var provider = flows.CreateProvider(pkceContext, (fact, prov) => prov.FlowType == OAuthHelper.CODE_FLOW_TYPE);
            if (provider == null) {
                Result.Outcome = TestOutcomes.Skipped;
                LogInfo("The authorization code grant is not working");
                return;
            }

            var processor = new PlainVerifier();
            provider.Pipeline.AddAfter<AddPKCEVerifier, Dictionary<string, string?>, Dictionary<string, string?>>(processor);

            var result = await provider.GetToken();
            if (result.AccessToken == null) {
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
                LogInfo("The token server detected the downgrade attack");
            } else {
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                LogInfo("The token server did not notice that the token exchange used PKCE, whereas the authorization request did not.");
            }
        }
        public class PlainVerifier : Processor<Dictionary<string, string?>, Dictionary<string, string?>> {
            public override Task<Dictionary<string, string?>?> Process(Dictionary<string, string?> value, IProvider tokenProvider, TokenResult tokenResult) {
                var acprov = tokenProvider as AuthorizationCodeTokenProvider;
                if (acprov != null) {
                    value["code_verifier"] = OAuthHelper.S256(acprov.CodeVerifier);
                } // else: we tried adding PKCE support for non AC-flows
                return Task.FromResult<Dictionary<string, string?>?>(value);
            }
        }
    }
}