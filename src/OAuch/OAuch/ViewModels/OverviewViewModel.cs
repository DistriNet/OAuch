using OAuch.Database.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OAuch.ViewModels {
    public class OverviewViewModel : IMenuInformation {
        public IList<Site>? Sites { get; set; }
        public Site? ActiveSite { get; set; }
        public PageType PageType { get; set; }


        public required Guid SiteId { get; set; }
        public required string SiteName { get; set; }
        //public DateTime? LatestResult { get; set; }
        public SettingsStatus AuthorizationUri { get; set; }
        public SettingsStatus TokenUri { get; set; }
        public SettingsStatus ClientId { get; set; }
        public SettingsStatus ClientSecret { get; set; }
        public SettingsStatus TestUri { get; set; }
        public int SelectedDocuments { get; set; }
    }
    public enum SettingsStatus : int {
        Empty = 0,
        Incomplete = 1,
        Disabled = 2,
        Ok = 3
    }
}
