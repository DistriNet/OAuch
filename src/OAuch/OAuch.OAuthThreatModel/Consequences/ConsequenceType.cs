namespace OAuch.OAuthThreatModel.Consequences {
    public class ConsequenceType {
        private ConsequenceType(string name, string description, bool isVulnerability) {
            this.Name = name;
            this.Description = description;
            this.IsVulnerability = isVulnerability;
        }

        public string Name { get; }
        public string Description { get; }
        public bool IsVulnerability { get; }

        internal static ConsequenceType CreateConsequence(string name, string description) {
            return new ConsequenceType(name, description, false);
        }
        internal static ConsequenceType CreateVulnerability(string name, string description) {
            return new ConsequenceType(name, description, true);
        }
    }
}
