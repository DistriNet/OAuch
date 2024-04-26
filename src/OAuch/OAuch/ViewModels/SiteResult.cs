using OAuch.Compliance.Results;
using System;

namespace OAuch.ViewModels {
    public class SiteResult {
        public required Guid SiteId { get; init; }
        public required string SiteName { get; init; }
        public required ComplianceResult Result { get; init; }
    }
}
