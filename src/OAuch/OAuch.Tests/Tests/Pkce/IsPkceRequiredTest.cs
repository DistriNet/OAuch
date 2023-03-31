using OAuch.Compliance.Tests.Features;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.Pkce {
    public class IsPkceRequiredTest : Test {
        public override string Title => "Does the server require PKCE";
        public override string Description => "This test determines whether the server requires the use of PKCE for the authorization code grant.";
        public override string? TestingStrategy => null;
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(IsPkceRequiredTestResult);
    }
    public class IsPkceRequiredTestResult : TestResult {
        public IsPkceRequiredTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(IsPkceRequiredTestImplementation);
    }
    public class IsPkceRequiredTestImplementation : TestImplementation {
        public IsPkceRequiredTestImplementation(TestRunContext context, IsPkceRequiredTestResult result, IsPkceImplementedTestResult pkce) : base(context, result, pkce) { }
        public override Task Run() {
            if (HasFailed<IsPkceImplementedTestResult>()) {
                Result.Outcome = TestOutcomes.Skipped;
                return Task.CompletedTask;
            }

            var supportedTypes = Context.State.Get<List<PKCESupportTypes>>(StateKeys.WorkingPkceTypes);
            if (supportedTypes.Contains(PKCESupportTypes.None)) {
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                LogInfo("The server supports the authorization code grant without PKCE");
            } else {
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
                LogInfo("The server requires PKCE");
            }
            return Task.CompletedTask;
        }
    }
}