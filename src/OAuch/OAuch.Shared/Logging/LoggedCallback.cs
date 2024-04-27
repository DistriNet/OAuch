namespace OAuch.Shared.Logging {
    public class LoggedCallback : LoggedItem {
        public LoggedCallback() {
            this.Url = string.Empty;
            this.FormData = string.Empty;
        }
        public string Url { get; set; }
        public string FormData { get; set; }

        public override void Accept(ILogVisitor formatter) {
            formatter.Visit(this);
        }
    }
}
