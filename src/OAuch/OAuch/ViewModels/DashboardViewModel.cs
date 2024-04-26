using OAuch.Database.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OAuch.ViewModels {
    public class DashboardViewModel : IMenuInformation {
        public IList<Site>? Sites { get; set; }
        public Site? ActiveSite { get; set; }
        public PageType PageType { get; set; }

        //public Dictionary<Site, DateTime> SiteDeadlines { get; set; }
        public required List<SiteResult> SiteResults { get; set; }
    }
}