using OAuch.Database.Entities;
using System.Collections.Generic;

namespace OAuch.ViewModels {
    public class CertificatesViewModel : IMenuInformation {
        public IList<Site>? Sites { get; set; }
        public Site? ActiveSite { get; set; }
        public PageType PageType { get; set; }

        public ICollection<SavedCertificate>? Certificates { get; set; }
        public string? Password { get; set; }
    }
}
