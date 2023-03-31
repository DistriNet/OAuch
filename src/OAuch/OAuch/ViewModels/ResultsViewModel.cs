using OAuch.Compliance.Results;
using OAuch.Database.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OAuch.ViewModels {
    public class ResultsViewModel : IMenuInformation {
        public Guid ResultId { get; set; }
        public IList<Site>? Sites { get; set; }
        public Site? ActiveSite { get; set; }
        public Guid SiteId { get; set; }
        public PageType PageType { get; set; }
        public DateTime StartedAt { get; set; }
        public ComplianceResult Result { get; set; }
        public IEnumerable<HistoryEntry> History { get; set; }
    }
    public class HistoryEntry {
        public Guid HistoryId { get; set; }
        public DateTime When { get; set; }
    }
}