using OAuch.Compliance.Tests.Features;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.Shared {
    public class ClientSecretEntropyInfo {
        public double? Entropy { get; set; }
    }
    public abstract class ClientSecretEntropyTestImplementationBase : TestImplementation<ClientSecretEntropyInfo> {
        public ClientSecretEntropyTestImplementationBase(TestRunContext context, TestResult<ClientSecretEntropyInfo> result, TestResult<ClientSecretEntropyInfo>? dependsOn, double minEntropy, HasSupportedFlowsTestResult supportedFlows) : base(context, result, supportedFlows) {
            _minEntropy = minEntropy;
            _dependsOn = dependsOn;
        }
        public override Task Run() {
            if (_dependsOn != null && _dependsOn.Outcome != TestOutcomes.SpecificationFullyImplemented) {
                Result.Outcome = TestOutcomes.Skipped;
                return Task.CompletedTask;
            }

            var secret = Context.SiteSettings.DefaultClient.ClientSecret;
            if (HasFailed<HasSupportedFlowsTestResult>() || string.IsNullOrWhiteSpace(secret)) {
                Result.Outcome = TestOutcomes.Skipped;
                return Task.CompletedTask;
            }

            ExtraInfo.Entropy = secret.CalculateEntropy() * secret.Length;

            LogInfo($"The calculated entropy of the client secret is { ExtraInfo.Entropy:F1} bits");
            if (ExtraInfo.Entropy < _minEntropy) {
                LogInfo($"The entropy is below the required { _minEntropy } bits");
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
            } else {
                LogInfo($"The entropy is above the required { _minEntropy } bits");
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
            }
            return Task.CompletedTask;
        }

        private double _minEntropy;
        private TestResult<ClientSecretEntropyInfo>? _dependsOn;
    }
}
