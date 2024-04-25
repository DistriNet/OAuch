using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Database.Entities {
    public class UserSession {
        public string Scheme { get; set; } = string.Empty;
        public string LoginId { get; set; } = string.Empty;
        public Guid InternalId { get; set; }
        public string? RemoteIp { get; set; }
        public DateTime? LoggedInAt { get; set; }
    }
}
