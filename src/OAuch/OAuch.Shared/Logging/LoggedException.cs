namespace OAuch.Shared.Logging {
    public class LoggedException : LoggedItem {
        public string? Message { get; set; }
        public string? StackTrace { get; set; }
        public LoggedException? InnerException { get; set; }

        public override void Accept(ILogVisitor formatter) {
            formatter.Visit(this);
        }
    }
}