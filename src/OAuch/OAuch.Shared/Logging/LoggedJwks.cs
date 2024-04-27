namespace OAuch.Shared.Logging {
    public class LoggedJwks : LoggedItem {
        public LoggedJwks() {
            this.Content = string.Empty;
        }
        public string Content { get; set; }

        public override void Accept(ILogVisitor formatter) {
            formatter.Visit(this);
        }
    }
}
