using OAuch.Compliance.Tests.Features;
using OAuch.Protocols.OAuth2;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.Shared {
    public class EntropyInfo { 
        public double? ResponseCount { get; set; }
        public double? AverageEntropy { get; set; }
        public double? StdDev { get; set; }
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

            var entropies = TokenHelper.GetAllTokenResults(Context).Select(tr => tr != null ? _selector(tr) : null).Where(sv => sv != null).Select(sv => sv!.CalculateEntropy() * sv!.Length).ToList();
            
            if (entropies.Count == 0) {
                LogInfo("No relevant and valid authorization responses registered");
                Result.Outcome = TestOutcomes.Skipped;
            } else {
                (var average, var stddev) = entropies.GetStatistics();
                LogInfo($"Out of { entropies.Count } valid authorization responses, the average calculated entropy for the { _name } was { average:F1} (±{ stddev:F1}) bits");
                if (average < _minEntropy) {
                    LogInfo($"The average entropy is below the required { _minEntropy } bits");
                    Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                } else {
                    LogInfo($"The average entropy is above the required { _minEntropy } bits");
                    Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
                }
                ExtraInfo.ResponseCount = entropies.Count;
                ExtraInfo.AverageEntropy = average;
                ExtraInfo.StdDev = stddev;
            }
            return Task.CompletedTask;
        }

        private string _name;
        private double _minEntropy;
        private Func<ValidToken, string?> _selector;
        private TestResult<EntropyInfo>? _dependsOn;
    }
}
