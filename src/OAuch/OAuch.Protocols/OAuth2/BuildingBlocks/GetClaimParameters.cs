using OAuch.Protocols.OAuth2.Pipeline;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace OAuch.Protocols.OAuth2.BuildingBlocks {
    public class GetClaimParameters : Processor<bool, Dictionary<string, string?>> {
        public GetClaimParameters(bool refresh = false) {
            this.Refresh = refresh;
        }
        public bool Refresh { get; }
        public override Task<Dictionary<string, string?>?> Process(bool value, IProvider tokenProvider, TokenResult tokenResult) {
            var ret = new Dictionary<string, string?>();
            if (this.Refresh) {
                ret["grant_type"] = "refresh_token";
                ret["refresh_token"] = tokenResult.RefreshToken;
            } else {
                if (tokenResult.AuthorizationCode != null) {
                    ret["grant_type"] = "authorization_code";
                    ret["code"] = tokenResult.AuthorizationCode;
                    ret["state"] = "oauch_state_var"; // This caused DropBox, TypeForm and SurveyMonkey to fail :-/
                } else if (tokenResult.AuthorizationResponse?.DeviceCode != null) {
                    ret["grant_type"] = OAuthHelper.DEVICE_FLOW_TYPE;
                    ret["device_code"] = tokenResult.AuthorizationResponse.DeviceCode;
                } else {
                    ret["grant_type"] = tokenProvider.FlowType;
                }
            }
            return Task.FromResult<Dictionary<string, string?>?>(ret);
        }
    }
}
