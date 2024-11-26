using OAuch.Compliance.Threats;
using System.Linq;

namespace OAuch.ViewModels {
    public class ThreatViewModel {
        public ThreatViewModel(Threat t) {
            this.Threat = t;
            this.Instance = t.Instances.First();
        }
        public Threat Threat { get; set; }
        public ThreatInstance Instance { get; set; }
    }
}
