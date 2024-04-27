using System;
using System.ComponentModel.DataAnnotations;

namespace OAuch.Database.Entities {
    public class SavedCertificate {
        [Key]
        public Guid SavedCertificateId { get; set; }
        //[JsonIgnore]
        //public virtual OAuchUser Owner { get; set; }

        //[JsonIgnore]
        public Guid OwnerId { get; set; }

#pragma warning disable CS8618 // Non-nullable field is uninitialized. Consider declaring as nullable.
        public string Name { get; set; }

        public string? Password { get; set; }

        public byte[] Blob { get; set; }
#pragma warning restore CS8618 // Non-nullable field is uninitialized. Consider declaring as nullable.

    }
}
