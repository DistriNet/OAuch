using OAuch.Compliance.Results;
using System;

namespace OAuch.ViewModels {
    public class SiteResult {
        public Guid SiteId { get; set; }
        public string SiteName { get; set; }
        public ComplianceResult Result { get; set; }
    }
}
