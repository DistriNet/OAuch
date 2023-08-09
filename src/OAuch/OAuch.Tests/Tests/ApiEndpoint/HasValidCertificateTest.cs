using Newtonsoft.Json;
using OAuch.Compliance.Tests;
using OAuch.Compliance.Tests.Features;
using OAuch.Compliance.Tests.Shared;
using OAuch.Protocols.Http;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.ApiEndpoint {
    public class HasValidCertificateTest : Test {
        public override string Title => "Trusted API certificate";
        public override string Description => "This test determines whether the certificate that is being used by the API server is widely trusted.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(HasValidCertificateTestResult);
    }
    public class HasValidCertificateTestResult : TestResult<CertificateReport> {
        public HasValidCertificateTestResult(string testId) : base(testId) {}
        public override Type ImplementationType => typeof(HasValidCertificateTestImplementation);
    }
    public class HasValidCertificateTestImplementation : HasValidCertificateTestImplementationBase {
        public HasValidCertificateTestImplementation(TestRunContext context, HasValidCertificateTestResult result, HasSupportedFlowsTestResult supportedFlows) : base(context, result, context.SiteSettings.TestUri, supportedFlows) { }
    }
}