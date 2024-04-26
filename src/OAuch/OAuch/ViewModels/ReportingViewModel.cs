using OAuch.Compliance.Results;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OAuch.ViewModels {
    public class ReportingViewModel {
        public required bool IncludeSettings { get; set; }
        public required bool IncludeLog { get; set; }
        public required bool IncludeSucceededTests { get; set; }
        public required bool IncludeDeprecatedFeatures { get; set; }
        public required bool IncludeThreats { get; set; }
        public required bool IncludeIndividualTests { get; set; }

        public required Guid SiteId { get; set; }
        public required string SiteName { get; set; }
        public required Guid ResultId { get; set; }
        public required DateTime StartedAt { get; set; }
        public required ComplianceResult Result { get; set; }
    }
}
