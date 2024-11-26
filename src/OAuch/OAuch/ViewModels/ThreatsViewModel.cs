using OAuch.Compliance.Threats;
using System.Collections.Generic;

namespace OAuch.ViewModels {
    public class ThreatsViewModel {
        public required IReadOnlyList<Threat> Threats { get; set; }
    }
}
