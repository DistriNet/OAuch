using Microsoft.AspNetCore.Mvc.Rendering;
using OAuch.Database.Entities;
using OAuch.Shared.Settings;
using System.Collections.Generic;

namespace OAuch.ViewModels {
    public class SettingsViewModel : IMenuInformation {
        public SettingsViewModel() {
            this.Settings = new SiteSettings();
        }
        public SettingsViewModel(SiteSettings settings) {
            this.Settings = settings;
        }
        public SiteSettings Settings { get; set; }
        public string? SiteName { get; set; }
        public SelectList? Certificates { get; set; }

        public IList<Site>? Sites { get; set; }
        public Site? ActiveSite { get; set; }
        public PageType PageType { get; set; }
    }
}
