using OAuch.Compliance.Tests.Features;
using OAuch.Compliance.Tests.Shared;
using OAuch.Protocols.Http;
using OAuch.Shared;
using System;

namespace OAuch.Compliance.Tests.TokenEndpoint {
    public class HasCacheControlHeaderTest : Test {
        public override string Title => "Is cache control header present";
        public override string Description => "This test determines whether Cache-Control header is present in authorization endpoint responses";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(HasCacheControlHeaderTestResult);
    }
    public class HasCacheControlHeaderTestResult : TestResult {
        public HasCacheControlHeaderTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(HasCacheControlHeaderTestImplementation);
    }
    public class HasCacheControlHeaderTestImplementation : HasCacheHeaderImplementationBase {
        public HasCacheControlHeaderTestImplementation(TestRunContext context, HasCacheControlHeaderTestResult result, HasSupportedFlowsTestResult supportedFlows)
            : base(context, result, context.SiteSettings.TokenUri, CacheSettings.CacheControlNoStore, supportedFlows) { }
        protected override string FailedInfoMessage => "The server did not send the 'Cache-Control: no-store' response header";
    }
}
