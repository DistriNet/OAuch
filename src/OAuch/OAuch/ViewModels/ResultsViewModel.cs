using OAuch.Compliance.Results;
using OAuch.Database.Entities;
using System;
using System.Collections.Generic;

namespace OAuch.ViewModels {
    public class ResultsViewModel : IMenuInformation {
        public Guid ResultId { get; set; }
        public IList<Site>? Sites { get; set; }
        public Site? ActiveSite { get; set; }
        public Guid SiteId { get; set; }
        public PageType PageType { get; set; }
        public DateTime StartedAt { get; set; }
        public required ComplianceResult Result { get; set; }
        public required IEnumerable<HistoryEntry> History { get; set; }
        public bool SettingsChanged { get; set; }
    }
    public class HistoryEntry {
        public Guid HistoryId { get; set; }
        public DateTime When { get; set; }
    }
}