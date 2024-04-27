using OAuch.Compliance.Tests.Features;
using OAuch.Compliance.Tests.Shared;
using OAuch.Protocols.Http;
using OAuch.Shared;
using System;

namespace OAuch.Compliance.Tests.AuthEndpoint {
    public class HasValidCertificateTest : Test {
        public override string Title => "Trusted authorization certificate";
        public override string Description => "This test determines whether the certificate that is being used by the authorization server is widely trusted.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(HasValidCertificateTestResult);
    }
    public class HasValidCertificateTestResult : TestResult<CertificateReport> {
        public HasValidCertificateTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(HasValidCertificateTestImplementation);
    }
    public class HasValidCertificateTestImplementation : HasValidCertificateTestImplementationBase {
        public HasValidCertificateTestImplementation(TestRunContext context, HasValidCertificateTestResult result, HasSupportedFlowsTestResult supportedFlows) : base(context, result, context.SiteSettings.AuthorizationUri, supportedFlows) { }
    }
}
