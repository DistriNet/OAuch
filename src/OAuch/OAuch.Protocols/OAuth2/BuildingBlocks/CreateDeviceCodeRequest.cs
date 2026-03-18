namespace OAuch.Protocols.OAuth2.BuildingBlocks {
    /// <summary>
    /// Creates a device authorization endpoint request from the current parameter set.
    /// </summary>
    public class CreateDeviceCodeRequest : CreateRequestBase {
        public CreateDeviceCodeRequest()
            : base(ss => ss.DeviceAuthorizationUri!) { }
    }
}
