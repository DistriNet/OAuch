using OAuch.Protocols.OAuth2.Pipeline;
using System;
using System.Threading.Tasks;

namespace OAuch.Protocols.OAuth2.BuildingBlocks {
    /// <summary>
    /// Verifies that a device authorization endpoint URI is configured before running the device flow.
    /// </summary>
    public class CheckDeviceAuthorizationUri : Processor<bool, bool> {
        public override Task<bool> Process(bool value, IProvider tokenProvider, TokenResult tokenResult) {
            if (string.IsNullOrWhiteSpace(tokenProvider.SiteSettings.DeviceAuthorizationUri)) {
                tokenResult.UnexpectedError = new ArgumentException("The device authorization URI cannot be empty.");
                this.Succeeded = false;
            } else {
                this.Succeeded = true;
            }
            return Task.FromResult(this.Succeeded);
        }
    }
}
