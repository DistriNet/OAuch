using OAuch.OAuthThreatModel.Consequences;

namespace OAuch.OAuthThreatModel.Enrichers {
    public class PublicClientAC : Enricher {
        public override string Id => "OAuch.Compliance.Tests.TokenEndpoint.IsClientAuthenticationRequiredTest";

        public override string Description => "The client is a public client because it does not enforce the use of a client secret.";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.HasAuthorizationCode];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.IsPublicClient];

        protected override bool? RelevancyResult => false;
    }
    //public class PublicClientPW : Enricher { // IsClientAuthenticationRequiredTest is not reliable to make conclusions about the password flow
    //    public override string Id => "OAuch.Compliance.Tests.TokenEndpoint.IsClientAuthenticationRequiredTest";

    //    public override string Description => "The client is a public client because it does not enforce the use of a client secret.";

    //    public override ConsequenceType[] DependsOn => [ConsequenceTypes.ClientHoldsUserPassword];

    //    public override ConsequenceType[] Consequences => [ConsequenceTypes.IsPublicClient];

    //    protected override bool? RelevancyResult => false;
    //}
    //public class PublicClientCC : Enricher { // IsClientAuthenticationRequiredTest is not reliable to make conclusions about the password flow
    //    public override string Id => "OAuch.Compliance.Tests.TokenEndpoint.IsClientAuthenticationRequiredTest";

    //    public override string Description => "The client is a public client because it does not enforce the use of a client secret.";

    //    public override ConsequenceType[] DependsOn => [ConsequenceTypes.MachineToMachine];

    //    public override ConsequenceType[] Consequences => [ConsequenceTypes.IsPublicClient];

    //    protected override bool? RelevancyResult => false;
    //}
}