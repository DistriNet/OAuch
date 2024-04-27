using System.Collections.Generic;

namespace OAuch.Shared.Logging {
    public class LoggedTokenResult : LoggedItem {
        public override void Accept(ILogVisitor formatter) {
            formatter.Visit(this);
        }

        public string? AuthorizationCode { get; set; }
        public string? RefreshToken { get; set; }
        public IList<string>? AccessTokens { get; set; }
        public IList<string>? IdentityTokens { get; set; }

        public string? AuthorizationResponse { get; set; }

        public string? TokenResponse { get; set; }

        public LoggedException? Exception { get; set; }
    }
}
