using OAuch.Compliance.Results;
using OAuch.OAuthThreatModel;
using OAuch.OAuthThreatModel.Attackers;
using OAuch.OAuthThreatModel.Flows;
using OAuch.OAuthThreatModel.Threats;
using System;
using System.Collections;
using System.Collections.Generic;

namespace OAuch.ViewModels {
    public class AttacksViewModel {
        public Guid Id { get; set; } /* result id */
        public AttackReport AttackReport { get; set; }
        public Dictionary<string, ThreatReport> ThreatReports { get; set; }

        public IList<Flow> AllFlows { get; set; }
        public IList<Threat> AllUnmitigatedThreats { get; set; }
        public IList<Threat> AllPartialThreats { get; set; }
        public IList<string>? SelectedFilter { get; set; }
        public IEnumerable<AttackerType> AttackerTypes { get; set; }
    }
}
