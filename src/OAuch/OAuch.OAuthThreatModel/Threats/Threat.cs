﻿using OAuch.OAuthThreatModel.Consequences;
using OAuch.OAuthThreatModel.Enrichers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Threats {
    public abstract class Threat : ModelElement {
        /// <summary>
        /// The description of the countermeasures for the threat
        /// </summary>
        public abstract string[] Countermeasures { get; }

        public override bool IsRelevant(IThreatModelContext context) {
            if (!base.IsRelevant(context))
                return false;
            if (context.IsThreatUnmitigated(this.Id) == false) // if the threat is unmitigated, it is relevant
                return true;
            return false;
        }

        public static IList<Threat> All {
            get {
                if (_allThreats == null) {
                    _allThreats = FindElements<Threat>();
                }
                return _allThreats;
            }
        }
        private static IList<Threat>? _allThreats;
    }
}
