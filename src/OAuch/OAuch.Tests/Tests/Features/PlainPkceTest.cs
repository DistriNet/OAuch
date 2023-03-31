using OAuch.Compliance.Tests.Pkce;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.Features {
    public class PlainPkceTest : Test {
        public override string Title => "Does the server support plain PKCE";
        public override string Description => "This test determines whether the server supports plain PKCE.";
        public override string? TestingStrategy => null;
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(PlainPkceTestResult);
    }
    public class PlainPkceTestResult : TestResult {
        public PlainPkceTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(PlainPkceTestImplementation);
    }
    public class PlainPkceTestImplementation : TestImplementation {
        public PlainPkceTestImplementation(TestRunContext context, PlainPkceTestResult result, IsPkceImplementedTestResult pkce) : base(context, result, pkce) { }
        public override Task Run() {
            if (HasFailed<IsPkceImplementedTestResult>()) {
                Result.Outcome = TestOutcomes.Skipped;
                return Task.CompletedTask;
            }

            var supportedTypes = Context.State.Get<List<PKCESupportTypes>>(StateKeys.WorkingPkceTypes);
            if (supportedTypes.Contains(PKCESupportTypes.Plain)) {
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
                LogInfo("The server supports plain PKCE");
            } else {
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                LogInfo("The server does not support plain PKCE");
            }
            return Task.CompletedTask;
        }
    }
}
