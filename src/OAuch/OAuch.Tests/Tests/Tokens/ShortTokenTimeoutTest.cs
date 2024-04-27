using OAuch.Compliance.Tests.Features;
using OAuch.Shared;
using System;

namespace OAuch.Compliance.Tests.Tokens {
    public class ShortTokenTimeoutTest : Test {
        public override string Title => "Do access tokens have a very short timeout";
        public override string Description => "This test checks if access tokens time out after at most 10 minutes.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(TokenTimeoutTestResult);
    }
    public class ShortTokenTimeoutTestResult : TokenTimeoutTestResult {
        public ShortTokenTimeoutTestResult(string testId) : base(testId) { }
    }
    public class ShortTokenTimeoutTestImplementation : TokenTimeoutTestImplementation {
        public ShortTokenTimeoutTestImplementation(TestRunContext context, ShortTokenTimeoutTestResult result, HasSupportedFlowsTestResult flows) : base(context, result, flows) { }

        public override int MaxTimeout { // in seconds
            get {
                return 600;
            }
        }
    }
}
