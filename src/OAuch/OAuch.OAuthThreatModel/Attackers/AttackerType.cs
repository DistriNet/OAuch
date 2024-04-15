using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Attackers {
    public class AttackerType {
        public AttackerType(string name, string description) {
            this.Name = name;
            this.Description = description;
        }

        public string Name { get; }
        public string Description { get; }
    }
}
