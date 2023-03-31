using OAuch.Compliance.Tests;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Results {
    public class ComplianceReport {
        public ComplianceReport(IList<TestResult> results, IEnumerable<DocumentTestRequirementLevel> deprecatedFeatures, IEnumerable<DocumentTestRequirementLevel> countermeasures) {
            this.DeprecatedFeatures = deprecatedFeatures.Select(df => new SpecificationCompliance(df, results, true)).ToList();
            if (this.DeprecatedFeatures.Any(df => df.IsCompliant == false))
                this.HasDeprecatedFeaturesEnabled = true;
            else if (this.DeprecatedFeatures.Any(df => df.IsCompliant == null))
                this.HasDeprecatedFeaturesEnabled = null;
            else
                this.HasDeprecatedFeaturesEnabled = false;

            this.Countermeasures = countermeasures.Select(df => new SpecificationCompliance(df, results)).ToList();
            this.OverallScore = new ComplianceScore(this.Countermeasures.Where(c => c.TestResult != null).Select(c => c.TestResult!));
            this.MustScore = new ComplianceScore(this.Countermeasures.Where(c => c.TestResult != null && c.RequirementLevel == RequirementLevels.Must).Select(c => c.TestResult!));
            this.ShouldScore = new ComplianceScore(this.Countermeasures.Where(c => c.TestResult != null && c.RequirementLevel == RequirementLevels.Should).Select(c => c.TestResult!));
            this.MayScore = new ComplianceScore(this.Countermeasures.Where(c => c.TestResult != null && c.RequirementLevel == RequirementLevels.May).Select(c => c.TestResult!));

        }
        public IList<SpecificationCompliance> DeprecatedFeatures { get; }
        public IList<SpecificationCompliance> Countermeasures { get; }
        public bool? HasDeprecatedFeaturesEnabled { get; }
        /// <summary>
        /// Overall countermeasure score
        /// </summary>
        public ComplianceScore OverallScore { get; }
        /// <summary>
        /// Overall MUST-countermeasure score
        /// </summary>
        public ComplianceScore MustScore { get; }
        /// <summary>
        /// Overall SHOULD-countermeasure score
        /// </summary>
        public ComplianceScore ShouldScore { get; }
        /// <summary>
        /// Overall MAY-countermeasure score
        /// </summary>
        public ComplianceScore MayScore { get; }
    }
}
