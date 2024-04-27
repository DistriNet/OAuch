using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.Pkce {
    public class HashedPkceDisabledTest : Test {
        public override string Title => "Does the server support hashed PKCE";
        public override string Description => "This test determines whether the server supports hashed PKCE.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(HashedPkceDisabledTestResult);
    }
    public class HashedPkceDisabledTestResult : TestResult {
        public HashedPkceDisabledTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(HashedPkceDisabledTestImplementation);
    }
    public class HashedPkceDisabledTestImplementation : TestImplementation {
        public HashedPkceDisabledTestImplementation(TestRunContext context, HashedPkceDisabledTestResult result, IsPkceImplementedTestResult pkce) : base(context, result, pkce) { }
        public override Task Run() {
            if (HasFailed<IsPkceImplementedTestResult>()) {
                Result.Outcome = TestOutcomes.Skipped;
                return Task.CompletedTask;
            }

            var supportedTypes = Context.State.Get<List<PKCESupportTypes>>(StateKeys.WorkingPkceTypes);
            if (!supportedTypes.Contains(PKCESupportTypes.Hash)) {
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                LogInfo("The server actively prohibits the use of hashed PKCE");
            } else {
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
                LogInfo("The server supports hashed PKCE");
            }
            return Task.CompletedTask;
        }
    }
}
