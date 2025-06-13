using OAuch.Compliance.Tests.Features;
using OAuch.Protocols.OAuth2;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.Shared {
    public class EntropyInfo {
        public double? ResponseCount { get; set; }
        public double? AverageEntropy { get; set; }
    }
    public abstract class EntropyTestImplementationBase : TestImplementation<EntropyInfo> {
        public EntropyTestImplementationBase(TestRunContext context, TestResult<EntropyInfo> result, TestResult<EntropyInfo>? dependsOn, string name, double minEntropy, Func<ValidToken, string?> selector, HasSupportedFlowsTestResult supportedFlows) : base(context, result, supportedFlows) {
            _name = name;
            _selector = selector;
            _minEntropy = minEntropy;
            _dependsOn = dependsOn;
        }
        public override Task Run() {
            if (_dependsOn != null && _dependsOn.Outcome != TestOutcomes.SpecificationFullyImplemented) {
                Result.Outcome = TestOutcomes.Skipped;
                return Task.CompletedTask;
            }

            if (HasFailed<HasSupportedFlowsTestResult>()) {
                Result.Outcome = TestOutcomes.Skipped;
                return Task.CompletedTask;
            }

            var values = TokenHelper.GetAllTokenResults(Context).Select(tr => tr != null ? _selector(tr) : null).Where(sv => sv != null).ToList();
            if (values.Count == 0) {
                LogInfo("No relevant and valid authorization responses registered");
                Result.Outcome = TestOutcomes.Skipped;
            } else {
                var c = string.Concat(values);
                var average = (c.CalculateEntropy() * c.Length) / values.Count;
                LogInfo($"Out of {values.Count} valid authorization responses, the average calculated entropy for the {_name} was {average:F1} bits");
                if (average < _minEntropy) {
                    LogInfo($"The average entropy is below the required {_minEntropy} bits");
                    Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                } else {
                    LogInfo($"The average entropy is above the required {_minEntropy} bits");
                    Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
                }
                ExtraInfo.ResponseCount = values.Count;
                ExtraInfo.AverageEntropy = average;
            }
            return Task.CompletedTask;
        }

        private readonly string _name;
        private readonly double _minEntropy;
        private readonly Func<ValidToken, string?> _selector;
        private readonly TestResult<EntropyInfo>? _dependsOn;
    }
}
