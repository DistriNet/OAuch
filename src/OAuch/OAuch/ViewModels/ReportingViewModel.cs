using OAuch.Compliance.Results;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OAuch.ViewModels {
    public class ReportingViewModel {
        public bool IncludeSettings { get; set; }
        public bool IncludeLog { get; set; }
        public bool IncludeSucceededTests { get; set; }
        public bool IncludeSkippedTests { get; set; }
        public bool IncludeFailedTests { get; set; }
        public bool IncludePendingTests { get; set; }
        public Guid SiteId { get; set; }
        public string SiteName { get; set; }
        public Guid ResultId { get; set; }
        public DateTime StartedAt { get; set; }
        public ComplianceResult Result { get; set; }
    }
}
