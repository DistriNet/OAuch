namespace OAuch.Shared.Logging {
    public class LoggedRedirect : LoggedItem {
        public LoggedRedirect() {
            this.Url = string.Empty;
        }
        public string Url { get; set; }

        public override void Accept(ILogVisitor formatter) {
            formatter.Visit(this);
        }
    }
}
