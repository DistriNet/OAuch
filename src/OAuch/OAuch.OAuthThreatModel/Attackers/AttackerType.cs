using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Attackers {
    public class AttackerType {
        public AttackerType(string id, string name, string description) {
            this.Id = id;
            this.Name = name;
            this.Description = description;
        }
        public string Id { get; }
        public string Name { get; }
        public string Description { get; }
    }
}
