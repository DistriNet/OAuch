using OAuch.Compliance.Tests.Features;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.AuthEndpoint {
    public class HasFragmentTest : Test {
        public override string Title => "Does the authorization URL have a fragment";
        public override string Description => "This test checks that the authorization URL does not have a fragment.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesBadNoGood;
        public override Type ResultType => typeof(HasFragmentTestResult);
    }
    public class HasFragmentTestResult : TestResult {
        public HasFragmentTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(HasFragmentTestImplementation);
    }
    public class HasFragmentTestImplementation : TestImplementation {
        public HasFragmentTestImplementation(TestRunContext context, HasFragmentTestResult result, HasSupportedFlowsTestResult flows) : base(context, result, flows) { }

        public override Task Run() {
            var authUrl = Context.SiteSettings.AuthorizationUri;
            if (authUrl == null || !Uri.TryCreate(authUrl, UriKind.Absolute, out var uri)) {
                Result.Outcome = TestOutcomes.Skipped;
                return Task.CompletedTask;
            }

            var frag = uri.Fragment?.TrimStart('#');
            Result.Outcome = (frag != null && frag.Length > 0) ? TestOutcomes.SpecificationNotImplemented : TestOutcomes.SpecificationFullyImplemented;
            return Task.CompletedTask;
        }
    }
}
