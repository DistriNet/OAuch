using OAuch.Compliance.Results;
using System.Collections;
using System.Collections.Generic;

namespace OAuch.ViewModels {
    public class AttacksViewModel {
        public AttackReport AttackReport { get; set; }
        public Dictionary<string, ThreatReport> ThreatReports { get; set; }
    }
}
