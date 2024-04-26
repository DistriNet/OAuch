using OAuch.Compliance.Results;
using OAuch.Database.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OAuch.ViewModels {
    public class ResultsViewModel : IMenuInformation {
        public required Guid ResultId { get; set; }
        public IList<Site>? Sites { get; set; }
        public Site? ActiveSite { get; set; }
        public required Guid SiteId { get; set; }
        public PageType PageType { get; set; }
        public required DateTime StartedAt { get; set; }
        public required ComplianceResult Result { get; set; }
        public required IEnumerable<HistoryEntry> History { get; set; }
    }
    public class HistoryEntry {
        public Guid HistoryId { get; set; }
        public DateTime When { get; set; }
    }
}