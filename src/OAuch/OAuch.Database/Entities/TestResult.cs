using System;
using System.ComponentModel.DataAnnotations;

namespace OAuch.Database.Entities {
    public class SerializedTestRun {
        [Key]
        public Guid TestResultId { get; set; }

        public Guid SiteId { get; set; }
        public DateTime StartedAt { get; set; }

#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.
        public string SelectedDocumentIdsJson { get; set; }
        public string ConfigurationJson { get; set; }
        public string TestResultsJson { get; set; }
        public string StateCollectionJson { get; set; }
#pragma warning restore CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.
    }
}
