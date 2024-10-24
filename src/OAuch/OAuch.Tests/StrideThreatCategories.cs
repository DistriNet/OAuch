using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance {
    [Flags]
    public enum StrideThreatCategories : int {
        /// <summary>
        /// Pretending to be something or someone other than yourself
        /// </summary>
        Spoofing = 0b1,
        /// <summary>
        /// Modifying something on disk, network, memory, or elsewhere
        /// </summary>
        Tampering = 0b10,
        /// <summary>
        /// Claiming that you didn't do something or were not responsible; can be honest or false
        /// </summary>
        Repudiation = 0b100,
        /// <summary>
        /// Someone obtaining information they are not authorized to access
        /// </summary>
        InformationDisclosure = 0b1000,
        /// <summary>
        /// Exhausting resources needed to provide service
        /// </summary>
        DenialOfService = 0b10000,
        /// <summary>
        /// Allowing someone to do something they are not authorized to do
        /// </summary>
        ElevationOfPrivilege = 0b100000
    }
}
