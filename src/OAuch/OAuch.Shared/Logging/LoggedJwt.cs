namespace OAuch.Shared.Logging {
    public class LoggedJwt : LoggedItem {
        public LoggedJwt() {
            this.Content = string.Empty;
        }
        public string Content { get; set; }

        public override void Accept(ILogVisitor formatter) {
            formatter.Visit(this);
        }
    }
}
