namespace OAuch.Shared.Logging {
    public class LoggedHttpResponse : LoggedItem {
        public LoggedHttpResponse() {
            this.Response = string.Empty;
        }
        public int StatusCode { get; set; }
        public string Response { get; set; }
        public string? Origin { get; set; }

        public override void Accept(ILogVisitor formatter) {
            formatter.Visit(this);
        }
    }
}
