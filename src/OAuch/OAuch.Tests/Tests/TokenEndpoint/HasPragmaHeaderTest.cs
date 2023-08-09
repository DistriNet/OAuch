using OAuch.Compliance.Tests.Features;
using OAuch.Compliance.Tests.Shared;
using OAuch.Protocols.Http;
using OAuch.Shared;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.TokenEndpoint {
    public class HasPragmaHeaderTest : Test {
        public override string Title => "Is pragma header present";
        public override string Description => "This test determines whether Pragma header is present in authorization endpoint responses";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(HasPragmaHeaderTestResult);
    }
    public class HasPragmaHeaderTestResult : TestResult {
        public HasPragmaHeaderTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(HasPragmaHeaderTestImplementation);
    }
    public class HasPragmaHeaderTestImplementation : HasCacheHeaderImplementationBase {
        public HasPragmaHeaderTestImplementation(TestRunContext context, HasPragmaHeaderTestResult result, HasSupportedFlowsTestResult supportedFlows)
            : base(context, result, context.SiteSettings.TokenUri, CacheSettings.PragmaNoCache, supportedFlows) { }
        protected override string FailedInfoMessage => "The server did not send the 'Pragma: no-cache' response header";
    }
}
