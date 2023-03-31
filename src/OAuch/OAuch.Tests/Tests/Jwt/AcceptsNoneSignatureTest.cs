using OAuch.Compliance.Tests.Features;
using OAuch.Protocols.Http;
using OAuch.Protocols.JWT;
using OAuch.Protocols.OAuth2;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.Jwt {
    public class AcceptsNoneSignatureTest : Test {
        public override string Title => "Does the API server accept JWT tokens without a signature";

        public override string Description => "This test determines whether the API server accepts a JWT access token without a signature.";

        public override string? TestingStrategy => null;

        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesBadNoGood;

        public override Type ResultType => typeof(AcceptsNoneSignatureTestResult);
    }
    public class AcceptsNoneSignatureTestResult : TestResult {
        public AcceptsNoneSignatureTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(AcceptsNoneSignatureTestImplementation);
    }
    public class AcceptsNoneSignatureTestImplementation : TestImplementation {
        public AcceptsNoneSignatureTestImplementation(TestRunContext context, AcceptsNoneSignatureTestResult result, HasSupportedFlowsTestResult supportedFlows, TestUriSupportedTestResult testUri) : base(context, result, supportedFlows, testUri) { }
        public override async Task Run() {
            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null || HasFailed<TestUriSupportedTestResult>() || !flows.HasJwtAccessTokens) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var provider = flows.CreateProvider(Context, false, true, false, false);
            var token = await provider.GetToken();
            var jwtToken = JsonWebToken.CreateFromString(token.AccessToken, Context.Log);
            if (jwtToken == null) {
                Result.Outcome = TestOutcomes.Failed;
                return; // not a JWT token; weird
            }
            if (jwtToken.Header.Algorithm == JwtAlgorithm.None) {
                Result.Outcome = TestOutcomes.SpecificationNotImplemented; // we received an unsigned token!
                LogInfo("The authorization server returned an unsigned JWT token");
                return;
            }

            var tokenBuilder = JwtTokenBuilder.CreateFromToken(jwtToken);
            var result = await AcceptsEmptyToken(tokenBuilder, JwtAlgorithm.None);
            if (!result) {
                result = await AcceptsEmptyToken(tokenBuilder, new NoneCasedAlgorithm()); // some implementations do a case-sensitive check for 'none', e.g. https://insomniasec.com/blog/auth0-jwt-validation-bypass
            }
            if (result) {
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                LogInfo("The API server accepted the unsigned token");
            } else {
                // see if an invalid signature is detected
                if (jwtToken.Header.Algorithm != null)
                    result = await AcceptsToken(tokenBuilder.Build(jwtToken.Header.Algorithm, RandomKey(jwtToken.Header.Algorithm)));
                if (result) {
                    Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                    LogInfo("The API server accepted a token with a forged signature");
                } else {
                    Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
                    LogInfo("The API server rejected the modified token");
                }
            }

            Task<bool> AcceptsEmptyToken(JwtTokenBuilder builder, JwtAlgorithm algorithm) {
                var newAccessToken = builder.Build(algorithm, TokenKey.Empty);
                return AcceptsToken(newAccessToken);
            }
            async Task<bool> AcceptsToken(string newAccessToken) {
                var newToken = new TokenResult { AuthorizationResponse = ServerResponse.FromAccessToken(newAccessToken) };
                var req = new ApiRequest(Context);
                var response = await req.Send(newToken);
                return response.StatusCode.IsOk(); // the call to the API worked
            }
            TokenKey RandomKey(JwtAlgorithm alg) {
                if (alg.Name.StartsWith("HS"))
                    return TokenKey.FromBytes(new byte[20]);
                else if (alg.Name.StartsWith("RS") || alg.Name.StartsWith("PS"))
                    return TokenKey.FromRsa(RSA.Create());
                else if (alg.Name.StartsWith("ES"))
                    return TokenKey.FromECDsa(ECDsa.Create());
                return TokenKey.FromBytes(new byte[20]);
            }
        }

    private class NoneCasedAlgorithm : JwtAlgorithm {
            public NoneCasedAlgorithm() : base(1, "nOne") { }
            public override string Sign(byte[] tokenData, TokenKey key) {
                return string.Empty;
            }
            public override bool Verify(JsonWebToken token, TokenKey key) {
                return (key as EmptyTokenKey) != null;
            }
        }
    }
}
