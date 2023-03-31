using OAuch.Compliance.Tests.Features;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.ApiEndpoint {
    public class TokenAsQueryParameterDisabledTest : Test {
        public override string Title => "Can the token be passed via the query";
        public override string Description => "This test determines whether the server disallows passing the access token via a query parameter.";
        public override string? TestingStrategy => null;
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesBadNoGood;
        public override Type ResultType => typeof(TokenAsQueryParameterDisabledTestResult);
    }
    public class TokenAsQueryParameterDisabledTestResult : TestResult {
        public TokenAsQueryParameterDisabledTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(TokenAsQueryParameterDisabledTestImplementation);
    }
    public class TokenAsQueryParameterDisabledTestImplementation : TestImplementation {
        public TokenAsQueryParameterDisabledTestImplementation(TestRunContext context, TokenAsQueryParameterDisabledTestResult result, TokenAsQueryParameterTestResult query) : base(context, result, query) { }
        public override Task Run() {
            var query = GetDependency<TokenAsQueryParameterTestResult>(false);
            if (query == null || query.Outcome == TestOutcomes.Skipped) {
                Result.Outcome = TestOutcomes.Skipped;
                return Task.CompletedTask;
            }

            if (query.Outcome == TestOutcomes.SpecificationFullyImplemented)
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
            else
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
            return Task.CompletedTask;
        }
    }
}
