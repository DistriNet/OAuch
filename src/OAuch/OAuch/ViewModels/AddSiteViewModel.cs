using OAuch.Database.Entities;
using System.Collections.Generic;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace OAuch.ViewModels {
    public class AddSiteViewModel : IMenuInformation {
        [Required]
        [StringLength(35)]
        public string? Name { get; set; }
        [DisplayName("Metadata URL")]
        public string? MetadataUrl { get; set; }

        public IList<Site>? Sites { get; set; }
        public Site? ActiveSite { get; set; }
        public PageType PageType { get; set; }
    }
}
