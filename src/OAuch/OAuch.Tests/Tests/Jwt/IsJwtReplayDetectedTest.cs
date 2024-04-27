using OAuch.Compliance.Tests.Features;
using OAuch.Compliance.Tests.Shared;
using OAuch.Protocols.JWT;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.Jwt {
    public class IsJwtReplayDetectedTest : Test {
        public override string Title => "Are replayed JWT's detected";
        public override string Description => "This test checks if the authorization server detects replayed JWT's.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(IsJwtReplayDetectedTestResult);
    }
    public class IsJwtReplayDetectedTestResult : TestResult {
        public IsJwtReplayDetectedTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(IsJwtReplayDetectedTestImplementation);
    }
    public class IsJwtReplayDetectedTestImplementation : ModifyAuthenticationJwtTestImplementationBase {
        public IsJwtReplayDetectedTestImplementation(TestRunContext context, IsJwtReplayDetectedTestResult result, HasSupportedFlowsTestResult flows, SupportsJwtClientAuthenticationTestResult jwt) : base(context, result, flows, jwt) {
            _jti = Guid.NewGuid().ToString("N");
        }
        protected override void ModifyToken(JwtTokenBuilder builder) {
            builder.Claims["jti"] = _jti;
        }

        public async override Task Run() {
            LogInfo("Sending a valid token request");
            await base.Run();
            if (Result.Outcome != TestOutcomes.SpecificationNotImplemented) {
                Result.Outcome = TestOutcomes.Skipped;
                return; // weird; the server didn't accept our token request
            }

            LogInfo("Sending a token request that uses a JWT for client authentication that has the same JWT identifier");
            await base.Run();
            if (Result.Outcome == TestOutcomes.SpecificationFullyImplemented) {
                LogInfo("The server rejected the authorization request with the duplicate JWT");
            } else {
                LogInfo("The server did not reject the authorization request with the duplicate JWT");
            }
        }

        protected override bool LogResult => false;

        private readonly string _jti;
    }
}
