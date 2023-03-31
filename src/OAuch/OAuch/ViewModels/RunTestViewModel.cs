using OAuch.Database.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OAuch.ViewModels {
    public class RunTestViewModel : IMenuInformation {
        public IList<Site>? Sites { get; set; }
        public Site? ActiveSite { get; set; }
        public PageType PageType { get; set; }

        public Guid SiteId { get; set; }
    }
}
