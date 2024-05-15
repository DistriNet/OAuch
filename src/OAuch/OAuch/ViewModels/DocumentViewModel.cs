using OAuch.Compliance;

namespace OAuch.ViewModels {
    public class DocumentViewModel {
        public DocumentViewModel(OAuthDocument document) {
            this.Document = document;
        }
        public OAuthDocument Document { get; set; }
    }
}
