namespace OAuch.ViewModels {
    public class LogViewModel {
        public LogViewModel(string contents) {
            this.Contents = contents;
        }
        public string Contents { get; set; }
    }
}
