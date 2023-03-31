using OAuch.Compliance.Tests.Features;
using OAuch.Protocols.Http;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.Shared {
     public abstract class HasValidCertificateTestImplementationBase : TestImplementation<CertificateReport> {
        public HasValidCertificateTestImplementationBase(TestRunContext context, TestResult<CertificateReport> result, string? url, HasSupportedFlowsTestResult supportedFlows) : base(context, result, supportedFlows) {
            _url = url;
        }
        public override async Task Run() {
            if (string.IsNullOrWhiteSpace(_url) || HasFailed<HasSupportedFlowsTestResult>()) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            if ( !Uri.TryCreate(_url, UriKind.Absolute, out var uri))
                return;

            var report = await Http.GetSecurityReport(_url);
            if (report.ServerCertificate != null) {
                Log(report.ServerCertificate);
                ExtraInfo = report.ServerCertificate;
            }
            Result.Outcome = report.Check(SecurityChecks.ServerCertificateValid) ? TestOutcomes.SpecificationFullyImplemented : TestOutcomes.SpecificationNotImplemented;
        }

        private string? _url;
    }
}
