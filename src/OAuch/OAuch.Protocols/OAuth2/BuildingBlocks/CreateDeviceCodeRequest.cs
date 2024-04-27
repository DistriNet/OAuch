namespace OAuch.Protocols.OAuth2.BuildingBlocks {
    public class CreateDeviceCodeRequest : CreateRequestBase {
        public CreateDeviceCodeRequest()
            : base(ss => ss.DeviceAuthorizationUri!) { }
    }
}
