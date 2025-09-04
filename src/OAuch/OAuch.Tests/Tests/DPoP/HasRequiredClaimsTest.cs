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
using System.Security.Claims;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.DPoP {
    public class HasRequiredClaimsTest : Test {
        public override string Title => "Are all required DPoP claims present";
        public override string Description => "This test checks if the authorization server only accepts DPoP proofs that contain all required claims ('jti', 'htm', 'htu', 'iat', and 'ath' for API requests).";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(HasRequiredClaimsTestResult);
    }

    public class HasRequiredClaimsTestResult : TestResult {
        public HasRequiredClaimsTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(HasRequiredClaimsTestImplementation);
    }

    public class HasRequiredClaimsTestImplementation : TestImplementation {
        public HasRequiredClaimsTestImplementation(TestRunContext context, HasRequiredClaimsTestResult result, HasSupportedFlowsTestResult flows, IsDPoPSupportedTestResult dpop)
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
            var processor = new RemoveDPoPClaimProcessor();
            prov.Pipeline.Replace<AddDPoPHeader, HttpRequest, HttpRequest>(processor);

            var requiredClaims = new[] { "jti", "htm", "htu", "iat" };
            foreach (var claim in requiredClaims) {
                processor.ClaimToRemove = claim;
                var token = await prov.GetToken();
                if (token.AccessToken != null || token.IdentityToken != null) {
                    Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                    LogInfo($"The server accepted a DPoP proof without the required '{claim}' claim.");
                    return;
                }
            }
            Result.Outcome = TestOutcomes.SpecificationFullyImplemented;

            // Now test 'ath' claim (API request)
            var validProvider = flows.CreateProvider(Context, mustHaveDPoPTokens: true);
            if (validProvider == null) {
                return;
            }
            var validToken = await validProvider.GetToken();
            if (string.IsNullOrWhiteSpace(validToken.AccessToken)) {
                return;
            }

            // Use a custom ApiRequest that removes 'ath' from the DPoP proof
            var apiRequest = new RemoveAthApiRequest(Context);
            var response = await apiRequest.Send(validToken);
            if (response.StatusCode.IsOk()) {
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                LogInfo("The server accepted an API request with a DPoP proof missing the 'ath' claim.");
                return;
            }

            LogInfo("The server correctly rejected DPoP proofs missing required claims.");
        }

        // Processor to remove a specific claim from the DPoP proof
        public class RemoveDPoPClaimProcessor : Processor<HttpRequest, HttpRequest> {
            public string? ClaimToRemove { get; set; }
            public override Task<HttpRequest?> Process(HttpRequest value, IProvider provider, TokenResult tokenResult) {
                var dpop = OAuthHelper.CreateDPoPToken(provider.SiteSettings, value, null, tokenResult.AuthorizationDPoPNonce);
                if (dpop != null) {
                    var builder = JwtTokenBuilder.CreateFromToken(dpop);
                    if (builder != null && ClaimToRemove != null) {
                        builder.Claims.Remove(ClaimToRemove);
                        JsonWebKey key = JsonWebKey.Create(provider.SiteSettings.DPoPSigningKey)!;
                        value.Headers[HttpRequestHeaders.DPoP] = builder.Build(key.Algorithm!, key.TokenKey);
                        return Task.FromResult<HttpRequest?>(value);
                    }
                }
                this.Succeeded = false;
                return Task.FromResult<HttpRequest?>(null);
            }
        }

        // Custom ApiRequest that removes the 'ath' claim from the DPoP proof
        public class RemoveAthApiRequest : ApiRequest {
            public RemoveAthApiRequest(TestRunContext context) : base(context) { }
            protected override HttpRequest GetRequest(string uri, TokenResult token) {
                var req = base.GetRequest(uri, token);
                if (req.Headers.TryGetValue(HttpRequestHeaders.DPoP, out var dpop)) {
                    var builder = JwtTokenBuilder.CreateFromToken(dpop, Context.Log);
                    if (builder != null) {
                        builder.Claims.Remove("ath");
                        JsonWebKey key = JsonWebKey.Create(Context.SiteSettings.DPoPSigningKey)!;
                        req.Headers[HttpRequestHeaders.DPoP] = builder.Build(key.Algorithm!, key.TokenKey);
                    }
                }
                return req;
            }
        }
    }
}