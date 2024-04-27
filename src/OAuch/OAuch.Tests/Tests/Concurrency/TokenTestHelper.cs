using OAuch.Protocols.Http;
using OAuch.Protocols.OAuth2;
using OAuch.Protocols.OAuth2.BuildingBlocks;
using OAuch.Protocols.OAuth2.Pipeline;
using OAuch.Shared;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.Concurrency {
    internal class TokenTestHelper {
        public static async Task<bool> TestAccessToken(TestRunContext context, string token) {
            var tr = new TokenResult { AuthorizationResponse = ServerResponse.FromAccessToken(token) };
            var request = new ApiRequest(context);
            var response = await request.Send(tr);
            return response.StatusCode.IsOk();
        }
        public static async Task<(bool, string?)> TestRefreshToken(string token, TokenProvider provider) {
            var pipeline = ProviderPipeline.Start()
                .Then(new CheckTokenUri())
                .Then(new GetClaimParameters(true))
                .Then(new CreateTokenRequest())
                .Then(new SendRequest(UriTypes.TokenUri))
                .Then(new GetServerResponseFromHttpResponse())
                .FinishTokenResponse();
            var tokenResult = new TokenResult { AuthorizationResponse = ServerResponse.FromRefreshToken(token) };
            await pipeline.Run(provider, tokenResult);
            if (tokenResult.AccessToken == null)
                return (false, null);
            if (tokenResult.RefreshToken == null || tokenResult.RefreshToken == token)
                return (true, null);
            return (true, tokenResult.RefreshToken);
        }
    }
}