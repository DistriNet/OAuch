using OAuch.OAuthThreatModel.Attackers;

namespace OAuch.OAuthThreatModel.Threats {
    public abstract class Threat : ModelElement {
        /// <summary>
        /// The description of the countermeasures for the threat; OAuch doesn't use this - it is here simply for completeness
        /// </summary>
        public abstract string[] Countermeasures { get; }

        /// <summary>
        /// The attacker types that can carry out the attack
        /// </summary>
        public abstract AttackerType[] Attackers { get; }

        public override bool IsRelevant(IThreatModelContext context) {
            if (context.IsThreatNotMitigated(this.Id) == true) // if the threat is not fully mitigated, it is relevant
                return true;
            return false;
        }

        public static List<Threat> All {
            get {
                _allThreats ??= FindElements<Threat>();
                return _allThreats;
            }
        }
        private static List<Threat>? _allThreats;

        public abstract List<StrideThreatCategories> StrideCategories { get; }
        public abstract List<CommunicatingParty> Parties { get; }
    }
}
