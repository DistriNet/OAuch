using OAuch.Compliance.Tests.DocumentSupport;
using OAuch.Protocols.Http;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.Revocation {
    public class IsRevocationEndpointSecureTest : Test {
        public override string Title => "Is the revocation endpoint secure";
        public override string Description => "This test determines whether the server's revocation endpoint uses HTTPS.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(IsRevocationEndpointSecureTestResult);
    }
    public class IsRevocationEndpointSecureTestResult : TestResult {
        public IsRevocationEndpointSecureTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(IsRevocationEndpointSecureTestImplementation);
    }
    public class IsRevocationEndpointSecureTestImplementation : TestImplementation {
        public IsRevocationEndpointSecureTestImplementation(TestRunContext context, IsRevocationEndpointSecureTestResult result, RFC7009SupportedTestResult rev) : base(context, result, rev) { }
        public override Task Run() {
            if (HasFailed<RFC7009SupportedTestResult>())
                Result.Outcome = TestOutcomes.Skipped;
            else
                Result.Outcome = Context.SiteSettings.RevocationUri!.IsSecure() ? TestOutcomes.SpecificationFullyImplemented : TestOutcomes.SpecificationNotImplemented;
            return Task.CompletedTask;
        }
    }
}
