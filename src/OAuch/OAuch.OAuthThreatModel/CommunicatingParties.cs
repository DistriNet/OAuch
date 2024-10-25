using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel {
    public static class CommunicatingParties {
        public static CommunicatingParty ClientToAS => new CommunicatingParty(Parties.Client, Parties.AuthorizationServer);
        public static CommunicatingParty ASToClient => new CommunicatingParty(Parties.AuthorizationServer, Parties.Client);
    }
    public class CommunicatingParty {
        public CommunicatingParty(Parties source, Parties dest) {
            this.Source = source;
            this.Destination = dest;
        }
        public Parties Source { get; }
        public Parties Destination { get; }

        public override bool Equals(object? obj) {
            return base.Equals(obj);
        }
        public override int GetHashCode() {
            return Source.GetHashCode() ^ Destination.GetHashCode();
        }
    }
    public enum Parties {
        ResourceOwner,
        UserAgent,
        Client,
        AuthorizationServer,
        ResourceServer
    }
}
