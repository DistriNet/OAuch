using OAuch.Compliance.Tests.Features;
using OAuch.Protocols.Http;
using OAuch.Protocols.JWT;
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

namespace OAuch.Compliance.Tests.DPoP {
    public class IsSignatureRequiredTest : Test {
        public override string Title => "Is a DPoP proof signature required";
        public override string Description => "This test attempts to obtain an access token while sending an unsigned (alg=none) DPoP proof and checks whether the authorization server rejects it.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(IsSignatureRequiredTestResult);
    }

    public class IsSignatureRequiredTestResult : TestResult {
        public IsSignatureRequiredTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(IsSignatureRequiredTestImplementation);
    }

    public class IsSignatureRequiredTestImplementation : TestImplementation {
        public IsSignatureRequiredTestImplementation(TestRunContext context, IsSignatureRequiredTestResult result, HasSupportedFlowsTestResult flows, IsDPoPSupportedTestResult dpop)
            : base(context, result, flows, dpop) { }

        public async override Task Run() {
            if (HasFailed<IsDPoPSupportedTestResult>()) { // no DPoP support
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            // Find a provider that uses the DPoP pipeline stage
            var prov = flows.CreateProviderWithStage<AddDPoPHeader, HttpRequest, HttpRequest>(Context);
            if (prov == null) {
                Result.Outcome = TestOutcomes.Skipped; // no provider that produces DPoP proofs
                return;
            }

            // Replace the standard DPoP header generator with one that produces an unsigned proof (alg=none)
            prov.Pipeline.Replace<AddDPoPHeader, HttpRequest, HttpRequest>(new UnsignedDPoPProcessor());

            var token = await prov.GetToken();
            if (token.AccessToken == null && token.IdentityToken == null) {
                // token issuance failed when unsigned DPoP was presented => server requires a signature
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
                LogInfo("The server rejected the unsigned DPoP proof.");
            } else {
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                LogInfo("The server issued a token despite an unsigned DPoP proof.");
            }
        }

        class UnsignedDPoPProcessor : Processor<HttpRequest, HttpRequest> {
            public override Task<HttpRequest?> Process(HttpRequest value, IProvider provider, TokenResult tokenResult) {
                // Attempt to create a normal DPoP token first (to get payload structure),
                // then re-build it with alg=none / empty key so the signature is absent.
                var good = OAuthHelper.CreateDPoPToken(provider.SiteSettings, value, null, tokenResult.AuthorizationDPoPNonce);
                if (good != null) {
                    var builder = JwtTokenBuilder.CreateFromToken(good);
                    if (builder != null) {
                        // Build unsigned token
                        value.Headers[HttpRequestHeaders.DPoP] = builder.Build(JwtAlgorithm.None, TokenKey.Empty);
                        return Task.FromResult<HttpRequest?>(value);
                    }
                }
                this.Succeeded = false;
                return Task.FromResult<HttpRequest?>(null);
            }
        }
    }
}