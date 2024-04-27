namespace OAuch.OAuthThreatModel.Enrichers {
    public abstract class Enricher : ModelElement {
        /// <summary>
        /// true if the testcase referenced in Id must be implemented, false if it should not be implemented,
        /// null if the test case is a dummy placeholder name
        /// </summary>
        protected virtual bool? RelevancyResult { get; } = null;

        public override bool IsRelevant(IThreatModelContext context) {
            return context.IsTestcaseImplemented(this.Id) == RelevancyResult;
        }

        public static List<Enricher> All {
            get {
                _allEnrichers ??= FindElements<Enricher>();
                return _allEnrichers;
            }
        }
        private static List<Enricher>? _allEnrichers;
    }
}
