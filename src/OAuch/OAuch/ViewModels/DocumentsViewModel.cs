using OAuch.Compliance;
using System.Collections.Generic;

namespace OAuch.ViewModels {
    public class DocumentsViewModel {
        public required IReadOnlyList<OAuthDocument> Documents { get; set; }
    }
}
