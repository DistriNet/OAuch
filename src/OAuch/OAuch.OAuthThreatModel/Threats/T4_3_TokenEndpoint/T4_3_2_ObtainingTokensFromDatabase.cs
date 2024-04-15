﻿using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Threats.TokenEndpoint
{
    public class T4_3_2_ObtainingTokensFromDatabase : Threat
    {
        public override string Description => "Obtaining Access Tokens from Authorization Server Database";

        public override string Id => "6819_4_3_2";

        public override ConsequenceType[] DependsOn => [];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.AccessTokenLeaked];

        public override string[] Countermeasures => [
            "Enforce system security measures",
            "Store access token hashes only",
            "Enforce standard SQL injection countermeasures"
            ];
    }
}