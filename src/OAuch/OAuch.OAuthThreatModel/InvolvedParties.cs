using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel {
    //public static class InvolvedParties {
    //    public static InvolvedParty Client => new InvolvedParty(Parties.Client);


    //    //public static InvolvedParty ClientToAS => new InvolvedParty(Parties.Client, Parties.AuthorizationServer);
    //    //public static InvolvedParty ASToClient => new InvolvedParty(Parties.AuthorizationServer, Parties.Client);
    //}
    //public class InvolvedParty {
    //    public InvolvedParty(params Parties[] parties) {
    //        this.Source = source;
    //        this.Destination = dest;
    //    }
    //    public Parties[] Source { get; }
    //    public Parties Destination { get; }

    //    public override bool Equals(object? obj) {
    //        return base.Equals(obj);
    //    }
    //    public override int GetHashCode() {
    //        return Source.GetHashCode() ^ Destination.GetHashCode();
    //    }
    //}
    public enum InvolvedParty {
        UserAgent,
        Client,
        AuthorizationEndpoint,
        TokenEndpoint,
        ResourceServer
    }
}
