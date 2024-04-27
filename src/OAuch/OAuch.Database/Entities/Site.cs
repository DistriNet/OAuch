using System;
using System.ComponentModel.DataAnnotations;

namespace OAuch.Database.Entities {
    public class Site {
        [Key]
        public Guid SiteId { get; set; }

        public Guid OwnerId { get; set; }

        public string Name { get; set; } = string.Empty;

        public string CurrentConfigurationJson { get; set; } = string.Empty;
        public Guid? LatestResultId { get; set; }

    }
}
