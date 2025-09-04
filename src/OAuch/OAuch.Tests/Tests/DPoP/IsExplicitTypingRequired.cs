using OAuch.Compliance.Tests.Features;
using OAuch.Protocols.Http;
using OAuch.Protocols.JWK;
using OAuch.Protocols.JWT;
using OAuch.Protocols.OAuth2;
using OAuch.Protocols.OAuth2.BuildingBlocks;
using OAuch.Protocols.OAuth2.Pipeline;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.DPoP {
    public class IsExplicitTypingRequiredTest : Test {
        public override string Title => "Is explicit typing required in DPoP proofs";
        public override string Description => "This test checks if the authorization server requires the 'typ' header to be set to 'dpop+JWT' in the DPoP proof.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(IsExplicitTypingRequiredTestResult);
    }

    public class IsExplicitTypingRequiredTestResult : TestResult {
        public IsExplicitTypingRequiredTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(IsExplicitTypingRequiredTestImplementation);
    }

    public class IsExplicitTypingRequiredTestImplementation : TestImplementation {
        public IsExplicitTypingRequiredTestImplementation(TestRunContext context, IsExplicitTypingRequiredTestResult result, HasSupportedFlowsTestResult flows, IsDPoPSupportedTestResult dpop)
            : base(context, result, flows, dpop) { }

        public override async Task Run() {
            if (HasFailed<IsDPoPSupportedTestResult>()) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var prov = flows.CreateProviderWithStage<AddDPoPHeader, HttpRequest, HttpRequest>(Context);
            if (prov == null) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var processor = new TypingDPoPProcessor();
            processor.RemoveTyp = false; // first, set typ = JWT
            prov.Pipeline.Replace<AddDPoPHeader, HttpRequest, HttpRequest>(processor);

            var token = await prov.GetToken();
            if (token.AccessToken == null && token.IdentityToken == null) {
                // now try without typ
                processor.RemoveTyp = true;
                var token2 = await prov.GetToken();
                if (token2.AccessToken == null && token2.IdentityToken == null) {
                    Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
                    LogInfo("The server requires the 'typ' header to be set to 'dpop+JWT' in DPoP proofs.");
                } else {
                    Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                    LogInfo("The server accepts DPoP proofs without 'typ' header.");
                }
            } else {
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                LogInfo("The server did accepted a DPoP proof with 'typ' set to 'JWT'.");
            }
        }

        public class TypingDPoPProcessor : Processor<HttpRequest, HttpRequest> {
            public bool RemoveTyp { get; set; } = false;
            public override Task<HttpRequest?> Process(HttpRequest value, IProvider provider, TokenResult tokenResult) {
                var dpop = OAuthHelper.CreateDPoPToken(provider.SiteSettings, value, null, tokenResult.AuthorizationDPoPNonce);
                if (dpop != null) {
                    var builder = JwtTokenBuilder.CreateFromToken(dpop);
                    if (builder != null) {
                        if (RemoveTyp) {
                            builder.Header.Remove("typ");
                        } else {
                            builder.Header["typ"] = "JWT";
                        }
                        JsonWebKey key = JsonWebKey.Create(provider.SiteSettings.DPoPSigningKey)!;
                        value.Headers[HttpRequestHeaders.DPoP] = builder.Build(key.Algorithm!, key.TokenKey);
                        return Task.FromResult<HttpRequest?>(value);
                    }
                }
                this.Succeeded = false;
                return Task.FromResult<HttpRequest?>(null);
            }
        }
    }
}