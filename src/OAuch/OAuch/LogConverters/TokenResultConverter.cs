using OAuch.Protocols.OAuth2;
using OAuch.Shared.Logging;

namespace OAuch.LogConverters {
    public class TokenResultConverter : ILogConverter<TokenResult> {
        public LoggedItem Convert(TokenResult item) {
            LoggedException? exception = null;
            //if (item.UnexpectedError != null) {
            //    var econv = ServiceLocator.Resolve<ILogConverter<Exception>>();
            //    exception = econv?.Convert(item.UnexpectedError) as LoggedException;
            //}

            return new LoggedTokenResult {
                AccessTokens = item.AllAccessTokens,
                IdentityTokens = item.AllIdentityTokens,
                RefreshToken = item.RefreshToken,
                AuthorizationCode = item.AuthorizationCode,
                TokenType = item.TokenResponse?.TokenType,
                AuthorizationResponse = item.AuthorizationResponse?.OriginalContents,
                TokenResponse = item.TokenResponse?.OriginalContents,
                Exception = exception
            };
        }
    }
}