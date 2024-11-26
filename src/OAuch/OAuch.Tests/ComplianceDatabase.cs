using OAuch.Compliance.Threats;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;

namespace OAuch.Compliance {
    public class ComplianceDatabase {


        private static List<Test>? _tests;
        public static IReadOnlyList<Test> AllTests {
            get {
                if (_tests == null) {
                    var l = new List<Test>();
                    var testType = typeof(Test);
                    var types = Assembly.GetExecutingAssembly().GetExportedTypes().Where(c => !c.IsAbstract && testType.IsAssignableFrom(c)).ToList();
                    foreach (var t in types) {
                        if (Activator.CreateInstance(t) is Test i) {
                            l.Add(i);
                        }
                    }
                    _tests = l;
                    return l;
                }
                return _tests;
            }
        }

        private static Dictionary<string, Test>? _testsDictionary;
        public static Dictionary<string, Test> Tests {
            get {
                if (_testsDictionary == null) {
                    _testsDictionary = [];
                    foreach (var test in AllTests) {
                        _testsDictionary[test.TestId] = test;
                    }
                }
                return _testsDictionary;
            }
        }

        public static Test? FindTestByResultType(Type resultType) {
            foreach (var t in AllTests) {
                if (t.ResultType == resultType)
                    return t;
            }
            return null;
        }

        private static List<Threat>? _threats;
        public static IReadOnlyList<Threat> AllThreats {
            get {
                _threats ??= [
                    new Threat_6819_4_1_1(),
                    new Threat_6819_4_1_2(),
                    new Threat_6819_4_1_3(),
                    new Threat_6819_4_1_5(),
                    new Threat_6819_4_2_1(),
                    new Threat_6819_4_2_3(),
                    new Threat_6819_4_2_4(),
                    new Threat_6819_4_3_1(),
                    new Threat_6819_4_3_3(),
                    new Threat_6819_4_3_5(),
                    new Threat_6819_4_4_1_1(),
                    new Threat_6819_4_4_1_3(),
                    new Threat_6819_4_4_1_5(),
                    new Threat_6819_4_4_1_7(),
                    new Threat_6819_4_4_1_8(),
                    new Threat_6819_4_4_1_9(),
                    new Threat_6819_4_4_1_13(),
                    new Threat_6819_4_4_2_2(),
                    new Threat_6819_4_4_3_1(),
                    new Threat_6819_4_4_3_2(),
                    new Threat_6819_4_4_3_3(),
                    new Threat_6819_4_4_3_4(),
                    new Threat_6819_4_5_1(),
                    new Threat_6819_4_5_2(),
                    new Threat_6819_4_5_3(),
                    new Threat_6819_4_5_4(),
                    new Threat_6819_4_6_1(),
                    new Threat_6819_4_6_2(),
                    new Threat_6819_4_6_3(),
                    new Threat_6819_4_6_6(),
                    new Threat_6819_4_6_7(),
                    new Threat_BCP_4_1_1(),
                    new Threat_BCP_4_1_2(),
                    new Threat_BCP_4_2_2(),
                    new Threat_BCP_4_3_1(),
                    new Threat_BCP_4_3_2_A(),
                    new Threat_BCP_4_3_2_B(),
                    new Threat_BCP_4_5(),
                    new Threat_BCP_4_7(),
                    new Threat_BCP_4_8(),
                    new Threat_BCP_4_10(),
                    new Threat_BCP_4_11_1(),
                    new Threat_BCP_4_11_2(),
                    new Threat_BCP_4_14(),
                    new Threat_BCP_4_16(),
                    new Threat_BCP_4_17(),
                    new Threat_7519_6(),
                    new Threat_7523(),
                    new Threat_7009_1(),
                    new Threat_7009_2(),
                    new Threat_OIDC_2(),
                    new Threat_OIDC_16(),
                    new Threat_MultiACConc()
                    ];
                return _threats;
            }
        }

        public static Dictionary<string, OAuthDocument> Documents {
            get {
                if (_docDictionary == null) {
                    _docDictionary = [];
                    foreach (var doc in AllDocuments) {
                        _docDictionary[doc.Id] = doc;
                    }
                }
                return _docDictionary;
            }
        }
        private static Dictionary<string, OAuthDocument>? _docDictionary;

        private static List<OAuthDocument>? _documents;
        public static IReadOnlyList<OAuthDocument> AllDocuments {
            get {
                _documents ??= [
                        new OAuthDocument {
                             Id = "RFC6749",
                             Name = "The OAuth 2.0 Authorization Framework",
                             Description = "The OAuth 2.0 authorization framework enables a third-party application to obtain limited access to an HTTP service, either on behalf of a resource owner by orchestrating an approval interaction between the resource owner and the HTTP service, or by allowing the third-party application to obtain access on its own behalf. This document is the base specification of OAuth 2.0.",
                             Url = "https://tools.ietf.org/html/rfc6749",
                             IsSupportedTest = "OAuch.Compliance.Tests.DocumentSupport.RFC6749SupportedTest",
                             IsStandard = true,
                             DocumentCategory = DocumentCategories.OAuth2,
                             DeprecatedFeatures = [
                                new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Features.IsDeprecatedTlsSupportedTest"],
                                     RequirementLevel = RequirementLevels.May,
                                     LocationInDocument = "1.6. TLS Version"
                                }
                             ],
                             Countermeasures= [
                                 // Auth endpoint tests
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.AuthEndpoint.HasValidCertificateTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "10.9. Ensuring Endpoint Authenticity"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.AuthEndpoint.IsModernTlsSupportedTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "1.6. TLS Version"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.AuthEndpoint.HasFragmentTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "3.1. Authorization Endpoint"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.AuthEndpoint.IsHttpsRequiredTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "3.1. Authorization Endpoint"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.AuthEndpoint.SupportsPostAuthorizationRequestsTest"],
                                     RequirementLevel = RequirementLevels.May,
                                     LocationInDocument = "3.1. Authorization Endpoint"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.AuthEndpoint.UnrecognizedParameterAllowedTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "3.1. Authorization Endpoint"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.AuthEndpoint.SameParameterTwiceDisallowedTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "3.1. Authorization Endpoint"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.AuthEndpoint.IsResponseTypeCheckedTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "3.1.1. Response Type"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.AuthEndpoint.RedirectUriFullyMatchedTest"],
                                     RequirementLevel = RequirementLevels.Should,
                                     LocationInDocument = "3.1.2.2. Registration Requirements"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.AuthEndpoint.CodePollutionTest"],
                                     RequirementLevel = RequirementLevels.Should,
                                     LocationInDocument = "3.1.2.2. Registration Requirements"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.AuthEndpoint.RedirectUriPathMatchedTest"],
                                     RequirementLevel = RequirementLevels.Should,
                                     LocationInDocument = "3.1.2.2. Registration Requirements"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.AuthEndpoint.RedirectUriConfusionTest"],
                                     RequirementLevel = RequirementLevels.Should,
                                     LocationInDocument = "3.1.2.2. Registration Requirements"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.AuthEndpoint.InvalidRedirectTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "3.1.2.4. Invalid Endpoint"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.AuthEndpoint.StatePresentTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "4.1.2. Authorization Response"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.AuthEndpoint.RefreshTokenPresentTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "4.2.2. Access Token Response"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.AuthEndpoint.HasFrameOptionsTest"],
                                     RequirementLevel = RequirementLevels.May,
                                     LocationInDocument = "10.13. Clickjacking"
                                 },
                                 // Token endpoint tests
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.HasValidCertificateTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "10.9. Ensuring Endpoint Authenticity"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.IsModernTlsSupportedTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "1.6. TLS Version"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.IsBasicAuthenticationSupportedTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "2.3.1. Client Password"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.IsAuthInUriAllowedTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "2.3.1. Client Password"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.IsClientAuthenticationRequiredTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "3.2.1. Client Authentication"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.IsHttpsRequiredTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "3.2.1. Client Authentication"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.IsGetSupportedTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "3.2. Token Endpoint"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.UnrecognizedParameterAllowedTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "3.2. Token Endpoint"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.SameParameterTwiceDisallowedTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "3.2. Token Endpoint"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.IsClientIdRequiredTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "3.2. Token Endpoint"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.MultipleCodeExchangesTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "4.1.2. Authorization Response"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.TokenValidAfterMultiExchangeTest"],
                                     RequirementLevel = RequirementLevels.Should,
                                     LocationInDocument = "4.1.2. Authorization Response"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.RefreshTokenValidAfterMultiExchangeTest"],
                                     RequirementLevel = RequirementLevels.Should,
                                     LocationInDocument = "4.1.2. Authorization Response"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.AuthorizationCodeTimeoutTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "10.5. Authorization Codes"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.IsCodeBoundToClientTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "4.1.2. Authorization Response"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.RedirectUriCheckedTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "4.1.3. Access Token Request"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.RefreshTokenPresentTest"],
                                     RequirementLevel = RequirementLevels.Should,
                                     LocationInDocument = "4.4.3. Access Token Response"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.HasCacheControlHeaderTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "5.1. Successful Response"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.HasPragmaHeaderTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "5.1. Successful Response"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.IsRefreshAuthenticationRequiredTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "6. Refreshing an Access Token"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.RefreshTokenRevokedAfterUseTest"],
                                     RequirementLevel = RequirementLevels.May,
                                     LocationInDocument = "6. Refreshing an Access Token"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.IsRefreshBoundToClientTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "10.4. Refresh Tokens"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.ClientSecretEntropyMinReqTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "10.10. Credentials-Guessing Attacks"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.ClientSecretEntropySugReqTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "10.10. Credentials-Guessing Attacks"
                                 },
                                 // Token tests
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Tokens.AuthorizationCodeEntropyMinReqTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "10.10. Credentials-Guessing Attacks"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Tokens.AuthorizationCodeEntropySugReqTest"],
                                     RequirementLevel = RequirementLevels.Should,
                                     LocationInDocument = "10.10. Credentials-Guessing Attacks"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Tokens.AccessTokenEntropyMinReqTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "10.10. Credentials-Guessing Attacks"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Tokens.AccessTokenEntropySugReqTest"],
                                     RequirementLevel = RequirementLevels.Should,
                                     LocationInDocument = "10.10. Credentials-Guessing Attacks"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Tokens.RefreshTokenEntropyMinReqTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "10.10. Credentials-Guessing Attacks"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Tokens.RefreshTokenEntropySugReqTest"],
                                     RequirementLevel = RequirementLevels.Should,
                                     LocationInDocument = "10.10. Credentials-Guessing Attacks"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.AuthEndpoint.RequireUserConsentTest"],
                                     RequirementLevel = RequirementLevels.Should,
                                     LocationInDocument = "10.2. Client Impersonation"
                                 },
                             ],
                             AdditionalTests = [
                                 Tests["OAuch.Compliance.Tests.Features.HasRefreshTokensTest"],
                                 Tests["OAuch.Compliance.Tests.Features.HasAccessTokensTest"],
                                 Tests["OAuch.Compliance.Tests.Features.CodeFlowSupportedTest"],
                                 Tests["OAuch.Compliance.Tests.Features.HasSupportedFlowsTest"],
                                 Tests["OAuch.Compliance.Tests.Features.ClientCredentialsFlowSupportedTest"],
                                 Tests["OAuch.Compliance.Tests.TokenEndpoint.IsPasswordFlowDisabledTest"],
                                 Tests["OAuch.Compliance.Tests.Features.HasSupportedFlowsTest"],
                                 Tests["OAuch.Compliance.Tests.Features.HasSupportedFlowsTest"],
                                 Tests["OAuch.Compliance.Tests.Features.HasJwtAccessTokensTest"],
                             ]
                        },
                        new OAuthDocument {
                            Id = "RFC6750",
                            Name ="The OAuth 2.0 Authorization Framework: Bearer Token Usage",
                            Description = "This specification describes how to use bearer tokens in HTTP requests to access OAuth 2.0 protected resources. Any party in possession of a bearer token can use it to get access to the associated resources (without demonstrating possession of a cryptographic key).",
                            Url = "https://tools.ietf.org/html/rfc6750",
                            IsSupportedTest = "OAuch.Compliance.Tests.DocumentSupport.RFC6750SupportedTest",
                            IsStandard = true,
                            DocumentCategory = DocumentCategories.OAuth2,
                            DeprecatedFeatures = [
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Features.TokenAsQueryParameterTest"],
                                     RequirementLevel = RequirementLevels.Should,
                                     LocationInDocument = "2.3. URI Query Parameter"
                                 },
                            ],
                            Countermeasures = [
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.ApiEndpoint.SupportsAuthorizationHeaderTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "2.1. Authorization Request Header Field"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.ApiEndpoint.CacheControlTest"],
                                     RequirementLevel = RequirementLevels.Should,
                                     LocationInDocument = "2.3. URI Query Parameter"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.ApiEndpoint.IsHttpsRequiredTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "5.2. Threat Mitigation"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.ApiEndpoint.HasValidCertificateTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "5.2. Threat Mitigation"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.ApiEndpoint.IsModernTlsSupportedTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "5.2. Threat Mitigation"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.AuthEndpoint.HasValidCertificateTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "5.2. Threat Mitigation"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.AuthEndpoint.IsModernTlsSupportedTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "5.2. Threat Mitigation"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.AuthEndpoint.IsHttpsRequiredTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "5.2. Threat Mitigation"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.HasValidCertificateTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "5.2. Threat Mitigation"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.IsModernTlsSupportedTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "5.2. Threat Mitigation"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.IsHttpsRequiredTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "5.2. Threat Mitigation"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Tokens.TokenTimeoutTest"],
                                     RequirementLevel = RequirementLevels.Should,
                                     LocationInDocument = "5.3. Summary of Recommendations"
                                 },
                            ],
                            AdditionalTests = [
                                 Tests["OAuch.Compliance.Tests.Features.TestUriSupportedTest"],
                                 Tests["OAuch.Compliance.Tests.ApiEndpoint.TokenAsQueryParameterDisabledTest"],
                             ]
                        },
                        new OAuthDocument {
                            Id = "RFC8628",
                            Name = "RFC8628 - OAuth 2.0 Device Authorization Grant",
                            Description = "The OAuth 2.0 device authorization grant is designed for Internet-connected devices that either lack a browser to perform a user-agent-based authorization or are input constrained to the extent that requiring the user to input text in order to authenticate during the authorization flow is impractical.",
                            Url = "https://tools.ietf.org/html/rfc8628",
                            IsSupportedTest = "OAuch.Compliance.Tests.DocumentSupport.RFC8628SupportedTest",
                            IsStandard = true,
                            DocumentCategory = DocumentCategories.OAuth2,
                            DeprecatedFeatures = [
                                new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Features.IsDeprecatedTlsSupportedTest"],
                                     RequirementLevel = RequirementLevels.May,
                                     LocationInDocument = "3.1. Device Authorization Request"
                                }
                            ],
                            Countermeasures = [
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.DeviceAuthEndpoint.HasValidCertificateTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "3.1. Device Authorization Request"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.DeviceAuthEndpoint.IsModernTlsSupportedTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "3.1. Device Authorization Request"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.DeviceAuthEndpoint.IsHttpsRequiredTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "3.1. Device Authorization Request"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.DeviceAuthEndpoint.UnrecognizedParameterAllowedTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "3.1. Device Authorization Request"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.DeviceAuthEndpoint.SameParameterTwiceDisallowedTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "3.1. Device Authorization Request"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.IsClientAuthenticationRequiredTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "3.4. Device Access Token Request"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.HasValidCertificateTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "3.4. Device Access Token Request"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.IsModernTlsSupportedTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "3.4. Device Access Token Request"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.IsHttpsRequiredTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "3.4. Device Access Token Request"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Tokens.DeviceCodeEntropyTest"],
                                     RequirementLevel = RequirementLevels.Should,
                                     LocationInDocument = "5.2. Device Code Brute Forcing"
                                 },
                            ],
                            AdditionalTests = [
                                 Tests["OAuch.Compliance.Tests.Features.DeviceFlowSupportedTest"],
                             ]
                        },
                        new OAuthDocument {
                            Id = "RFC7636",
                            Name = "Proof Key for Code Exchange by OAuth Public Clients",
                            Description = "OAuth 2.0 public clients utilizing the Authorization Code Grant are susceptible to the authorization code interception attack.  This specification describes the attack as well as a technique to mitigate against the threat through the use of Proof Key for Code Exchange (PKCE, pronounced 'pixy').",
                            Url = "https://tools.ietf.org/html/rfc7636",
                            IsSupportedTest = "OAuch.Compliance.Tests.DocumentSupport.RFC7636SupportedTest",
                            IsStandard = true,
                            DocumentCategory = DocumentCategories.OAuth2,
                            DeprecatedFeatures = [
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Features.PlainPkceTest"],
                                     RequirementLevel = RequirementLevels.Should,
                                     LocationInDocument = "4.2. Client Creates the Code Challenge"
                                 },
                            ],
                            Countermeasures = [
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Pkce.IsPkceImplementedTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "4.6. Server Verifies code_verifier before Returning the Tokens"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Pkce.HashedPkceDisabledTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "4.2. Client Creates the Code Challenge"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Pkce.IsPkceRequiredTest"],
                                     RequirementLevel = RequirementLevels.May,
                                     LocationInDocument = "5. Compatibility"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Pkce.IsPkceDowngradeDetectedTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "4.4. Server Returns the Code"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Pkce.IsPkceTokenDowngradeDetectedTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "4.4. Server Returns the Code"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Pkce.IsPkcePlainDowngradeDetectedTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "4.4. Server Returns the Code"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Pkce.ShortVerifierTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "4.1. Client Creates a Code Verifier"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.HasValidCertificateTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "7.5. TLS Security Considerations"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.IsModernTlsSupportedTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "7.5. TLS Security Considerations"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.IsHttpsRequiredTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "7.5. TLS Security Considerations"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.AuthEndpoint.HasValidCertificateTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "7.5. TLS Security Considerations"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.AuthEndpoint.IsModernTlsSupportedTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "7.5. TLS Security Considerations"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.AuthEndpoint.IsHttpsRequiredTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "7.5. TLS Security Considerations"
                                 },

                            ]
                        },
                        new OAuthDocument {
                            Id = "RFC6819",
                            Name = "OAuth 2.0 Threat Model and Security Considerations",
                            Description = "This document gives additional security considerations for OAuth, beyond those in the OAuth 2.0 specification, based on a comprehensive threat model for the OAuth 2.0 protocol.",
                            Url = "https://tools.ietf.org/html/rfc6819",
                            IsSupportedTest = "OAuch.Compliance.Tests.DocumentSupport.RFC6819SupportedTest",
                            IsStandard = true,
                            DocumentCategory = DocumentCategories.OAuth2,
                            DeprecatedFeatures = [],
                            Countermeasures = [
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.ApiEndpoint.IsHttpsRequiredTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "5.1.1. Ensure Confidentiality of Requests"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.ApiEndpoint.HasValidCertificateTest"],
                                     RequirementLevel = RequirementLevels.Should,
                                     LocationInDocument = "5.1.2. Utilize Server Authentication"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.ApiEndpoint.IsModernTlsSupportedTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "5.1.1. Ensure Confidentiality of Requests"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.AuthEndpoint.HasValidCertificateTest"],
                                     RequirementLevel = RequirementLevels.Should,
                                     LocationInDocument = "5.1.2. Utilize Server Authentication"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.AuthEndpoint.IsModernTlsSupportedTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "5.1.1. Ensure Confidentiality of Requests"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.AuthEndpoint.IsHttpsRequiredTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "5.1.1. Ensure Confidentiality of Requests"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.HasValidCertificateTest"],
                                     RequirementLevel = RequirementLevels.Should,
                                     LocationInDocument = "5.1.2. Utilize Server Authentication"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.IsModernTlsSupportedTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "5.1.1. Ensure Confidentiality of Requests"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.IsHttpsRequiredTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "5.1.1. Ensure Confidentiality of Requests"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.ClientSecretEntropyMinReqTest"],
                                     RequirementLevel = RequirementLevels.Should,
                                     LocationInDocument = "5.1.4.2.2. Use High Entropy for Secrets"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Tokens.AuthorizationCodeEntropyMinReqTest"],
                                     RequirementLevel = RequirementLevels.Should,
                                     LocationInDocument = "5.1.4.2.2. Use High Entropy for Secrets"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Tokens.AccessTokenEntropyMinReqTest"],
                                     RequirementLevel = RequirementLevels.Should,
                                     LocationInDocument = "5.1.4.2.2. Use High Entropy for Secrets"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Tokens.RefreshTokenEntropyMinReqTest"],
                                     RequirementLevel = RequirementLevels.Should,
                                     LocationInDocument = "5.1.4.2.2. Use High Entropy for Secrets"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Tokens.TokenTimeoutTest"],
                                     RequirementLevel = RequirementLevels.Should,
                                     LocationInDocument = "5.1.5.3. Use Short Expiration Time"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.MultipleCodeExchangesTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "5.2.1.1. Automatic Revocation of Derived Tokens If Abuse Is Detected"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.TokenValidAfterMultiExchangeTest"],
                                     RequirementLevel = RequirementLevels.May,
                                     LocationInDocument = "5.2.1.1. Automatic Revocation of Derived Tokens If Abuse Is Detected"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.RefreshTokenValidAfterMultiExchangeTest"],
                                     RequirementLevel = RequirementLevels.May,
                                     LocationInDocument = "5.2.1.1. Automatic Revocation of Derived Tokens If Abuse Is Detected"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.IsRefreshAuthenticationRequiredTest"],
                                     RequirementLevel = RequirementLevels.Should,
                                     LocationInDocument = "5.2.2.2. Binding of Refresh Token to 'client_id'"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.IsRefreshBoundToClientTest"],
                                     RequirementLevel = RequirementLevels.Should,
                                     LocationInDocument = "5.2.2.2. Binding of Refresh Token to 'client_id'"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.RefreshTokenRevokedAfterUseTest"],
                                     RequirementLevel = RequirementLevels.May,
                                     LocationInDocument = "5.2.2.3. Refresh Token Rotation"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.AuthEndpoint.HasFrameOptionsTest"],
                                     RequirementLevel = RequirementLevels.May,
                                     LocationInDocument = "5.2.2.6. X-FRAME-OPTIONS Header"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.IsClientAuthenticationRequiredTest"],
                                     RequirementLevel = RequirementLevels.Should,
                                     LocationInDocument = "5.2.3. Client Authentication and Authorization"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.AuthEndpoint.RequireUserConsentTest"],
                                     RequirementLevel = RequirementLevels.Should,
                                     LocationInDocument = "5.2.3.2. Require User Consent for Public Clients without Secret"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.AuthEndpoint.RedirectUriFullyMatchedTest"],
                                     RequirementLevel = RequirementLevels.Should,
                                     LocationInDocument = "5.2.3.3.  Issue a 'client_id' Only in Combination with 'redirect_uri'"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.AuthEndpoint.CodePollutionTest"],
                                     RequirementLevel = RequirementLevels.Should,
                                     LocationInDocument = "5.2.3.3.  Issue a 'client_id' Only in Combination with 'redirect_uri'"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.AuthEndpoint.RedirectUriPathMatchedTest"],
                                     RequirementLevel = RequirementLevels.Should,
                                     LocationInDocument = "5.2.3.3.  Issue a 'client_id' Only in Combination with 'redirect_uri'"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.AuthEndpoint.RedirectUriConfusionTest"],
                                     RequirementLevel = RequirementLevels.Should,
                                     LocationInDocument = "5.2.3.3.  Issue a 'client_id' Only in Combination with 'redirect_uri'"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.AuthEndpoint.InvalidRedirectTest"],
                                     RequirementLevel = RequirementLevels.Should,
                                     LocationInDocument = "5.2.3.5.  Validate Pre-Registered 'redirect_uri'"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.IsCodeBoundToClientTest"],
                                     RequirementLevel = RequirementLevels.Should,
                                     LocationInDocument = "5.2.4.4.  Binding of Authorization 'code' to 'client_id'"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.RedirectUriCheckedTest"],
                                     RequirementLevel = RequirementLevels.Should,
                                     LocationInDocument = "5.2.4.5. Binding of Authorization 'code' to 'redirect_uri'"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.IsBasicAuthenticationSupportedTest"],
                                     RequirementLevel = RequirementLevels.Should,
                                     LocationInDocument = "5.4.1. Authorization Headers"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.DocumentSupport.RFC7009SupportedTest"],
                                     RequirementLevel = RequirementLevels.May,
                                     LocationInDocument = "5.2.2.4. Revocation of Refresh Tokens"
                                 },
                            ],
                        },
                        new OAuthDocument {
                            Id = "RFC7523",
                            Name = "JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and Authorization Grants",
                            Description = "This specification defines the use of a JSON Web Token (JWT) Bearer Token as a means for requesting an OAuth 2.0 access token as well as for client authentication.",
                            Url = "https://tools.ietf.org/html/rfc7523",
                            IsSupportedTest = "OAuch.Compliance.Tests.DocumentSupport.RFC7523SupportedTest",
                            IsStandard = true,
                            DocumentCategory = DocumentCategories.OAuth2,
                            DeprecatedFeatures = [],
                            Countermeasures = [
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Jwt.SupportsJwtClientAuthenticationTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "2.2. Using JWTs for Client Authentication"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Jwt.HasIssuerClaimTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "3. JWT Format and Processing Requirements"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Jwt.HasSubjectClaimTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "3. JWT Format and Processing Requirements"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Jwt.HasAudienceClaimTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "3. JWT Format and Processing Requirements"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Jwt.IsExpirationCheckedTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "3. JWT Format and Processing Requirements"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Jwt.IsNotBeforeCheckedTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "3. JWT Format and Processing Requirements"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Jwt.IsIssuedAtCheckedTest"],
                                     RequirementLevel = RequirementLevels.May,
                                     LocationInDocument = "3. JWT Format and Processing Requirements"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Jwt.IsJwtReplayDetectedTest"],
                                     RequirementLevel = RequirementLevels.May,
                                     LocationInDocument = "3. JWT Format and Processing Requirements"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Jwt.IsSignatureRequiredTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "3. JWT Format and Processing Requirements"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Jwt.IsSignatureCheckedTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "3. JWT Format and Processing Requirements"
                                 },
                            ],
                        },
                        new OAuthDocument {
                            Id = "RFC7009",
                            Name = "OAuth 2.0 Token Revocation",
                            Description = "This document proposes an additional endpoint for OAuth authorization servers, which allows clients to notify the authorization server that a previously obtained refresh or access token is no longer needed. This allows the authorization server to clean up security credentials.",
                            Url = "https://tools.ietf.org/html/rfc7009",
                            IsSupportedTest = "OAuch.Compliance.Tests.DocumentSupport.RFC7009SupportedTest",
                            IsStandard = true,
                            DocumentCategory = DocumentCategories.OAuth2,
                            DeprecatedFeatures  = [],
                            Countermeasures= [
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Revocation.CanAccessTokensBeRevokedTest"],
                                     RequirementLevel = RequirementLevels.Should,
                                     LocationInDocument = "2. Token Revocation"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Revocation.CanRefreshTokensBeRevokedTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "2. Token Revocation"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Revocation.IsRevocationEndpointSecureTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "2. Token Revocation"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Revocation.IsModernTlsSupportedTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "2. Token Revocation"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Revocation.IsClientAuthRequiredTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "2.1. Revocation Request"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Revocation.IsBoundToClientTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "2.1. Revocation Request"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Revocation.AccessRevokesRefreshTest"],
                                     RequirementLevel = RequirementLevels.May,
                                     LocationInDocument = "2.1. Revocation Request"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Revocation.RefreshRevokesAccessTest"],
                                     RequirementLevel = RequirementLevels.Should,
                                     LocationInDocument = "2.1. Revocation Request"
                                 },

                            ]
                        },
                        /*new OAuthDocument {    // TODO: nobody supports it right now
                            Id = "RFC8705",
                            Name = "OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens",
                            Description = "This document describes OAuth client authentication and certificate-bound access and refresh tokens using mutual Transport Layer Security (TLS) authentication with X.509 certificates.",
                            Url = "https://tools.ietf.org/html/rfc8705",
                            IsSupportedTest = "",
                            DeprecatedFeatures = new  List<TestRequirementLevel> {
                                //
                            },
                            Countermeasures = new  List<TestRequirementLevel> {
                                //
                            },
                        },*/
                        //new OAuthDocument {
                        //    Id = "RFC8252",
                        //    Name = "OAuth 2.0 for Native Apps",
                        //    Description = "OAuth 2.0 authorization requests from native apps should only be made through external user-agents, primarily the user's browser.  This specification details the security and usability reasons why this is the case and how native apps and authorization servers can implement this best practice.",
                        //    Url = "https://tools.ietf.org/html/rfc8252",
                        //    IsSupportedTest = "OAuch.Compliance.Tests.DocumentSupport.RFC8252SupportedTest",
                        //    DeprecatedFeatures = new  List<TestRequirementLevel> {
                        //        //
                        //    },
                        //    Countermeasures = new  List<TestRequirementLevel> {
                        //        //
                        //    },
                        //},
                        new OAuthDocument {
                            Id = "SecBCP",
                            Name = "OAuth 2.0 Security Best Current Practice (draft 25)",
                            Description = "This document describes best current security practice for OAuth 2.0. It updates and extends the OAuth 2.0 Security Threat Model to incorporate practical experiences gathered since OAuth 2.0 was published and covers new threats relevant due to the broader application of OAuth 2.0.",
                            Url = "https://tools.ietf.org/html/draft-ietf-oauth-security-topics",
                            IsSupportedTest = "OAuch.Compliance.Tests.DocumentSupport.RFC6749SupportedTest",
                            IsStandard = false,
                            DocumentCategory = DocumentCategories.Draft,
                            DeprecatedFeatures  = [
                                new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Features.TokenFlowSupportedTest"],
                                     RequirementLevel = RequirementLevels.Should,
                                     LocationInDocument = "2.1.2 Implicit Grant"
                                },
                                new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Features.IdTokenTokenFlowSupportedTest"],
                                     RequirementLevel = RequirementLevels.Should,
                                     LocationInDocument = "2.1.2 Implicit Grant"
                                },
                                new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Features.CodeTokenFlowSupportedTest"],
                                     RequirementLevel = RequirementLevels.Should,
                                     LocationInDocument = "2.1.2 Implicit Grant"
                                },
                                new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Features.CodeIdTokenTokenFlowSupportedTest"],
                                     RequirementLevel = RequirementLevels.Should,
                                     LocationInDocument = "2.1.2 Implicit Grant"
                                },
                                new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Features.PasswordFlowSupportedTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "2.4. Resource Owner Password Credentials Grant"
                                },
                                new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Features.PlainPkceTest"],
                                     RequirementLevel = RequirementLevels.Should,
                                     LocationInDocument = "2.1.1. Authorization Code Grant"
                                },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Features.TokenAsQueryParameterTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "4.3.2. Access Token in Browser History"
                                 },
                             ],
                            Countermeasures= [
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.AuthEndpoint.RedirectUriFullyMatchedTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "2.1.  Protecting Redirect-Based Flows"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.AuthEndpoint.CodePollutionTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "2.1.  Protecting Redirect-Based Flows"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Pkce.IsPkceImplementedTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "2.1.1. Authorization Code Grant"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Pkce.IsPkceDowngradeDetectedTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "2.1.1. Authorization Code Grant"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Pkce.IsPkceTokenDowngradeDetectedTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "2.1.1. Authorization Code Grant"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Pkce.IsPkcePlainDowngradeDetectedTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "2.1.1. Authorization Code Grant"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Pkce.HashedPkceDisabledTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "2.1.1. Authorization Code Grant"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Pkce.IsPkceRequiredTest"],
                                     RequirementLevel = RequirementLevels.Should,
                                     LocationInDocument = "2.1.1. Authorization Code Grant"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Pkce.ShortVerifierTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "2.1.1. Authorization Code Grant"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.DocumentSupport.RFC8705SupportedTest"],
                                     RequirementLevel = RequirementLevels.Should,
                                     LocationInDocument = "2.2.1. Access Tokens"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.ApiEndpoint.AreBearerTokensDisabledTest"],
                                     RequirementLevel = RequirementLevels.Should,
                                     LocationInDocument = "2.2.1. Access Tokens"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.UsesTokenRotationTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "2.2.2. Refresh Tokens"
                                 },
                                 new TestRequirementLevel {
                                     Test = Tests["OAuch.Compliance.Tests.TokenEndpoint.IsRefreshAuthenticationRequiredTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "2.2.2. Refresh Tokens"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.IsClientAuthenticationRequiredTest"],
                                     RequirementLevel = RequirementLevels.Should,
                                     LocationInDocument = "2.5. Client Authentication"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.IsAsymmetricClientAuthenticationUsedTest"],
                                     RequirementLevel = RequirementLevels.Should,
                                     LocationInDocument = "2.5. Client Authentication"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.AuthEndpoint.FragmentFixTest"],
                                     RequirementLevel = RequirementLevels.May,
                                     LocationInDocument = "4.1.3. Countermeasures"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.AuthEndpoint.ReferrerPolicyEnforcedTest"],
                                     RequirementLevel = RequirementLevels.May,
                                     LocationInDocument = "4.2.4. Countermeasures"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.IsCodeBoundToClientTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "4.2.4. Countermeasures"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.MultipleCodeExchangesTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "4.2.4. Countermeasures"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.TokenValidAfterMultiExchangeTest"],
                                     RequirementLevel = RequirementLevels.Should,
                                     LocationInDocument = "4.2.4. Countermeasures"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.RefreshTokenValidAfterMultiExchangeTest"],
                                     RequirementLevel = RequirementLevels.Should,
                                     LocationInDocument = "4.2.4. Countermeasures"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.AuthEndpoint.SupportsPostResponseModeTest"],
                                     RequirementLevel = RequirementLevels.May,
                                     LocationInDocument = "4.2.4. Countermeasures"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.AuthEndpoint.InvalidRedirectTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "4.10.2. Authorization Server as Open Redirector"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.IsRefreshBoundToClientTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "4.13.2. Recommendations"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.InvalidatedRefreshTokenTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "4.13.2. Recommendations"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.AuthEndpoint.HasFrameOptionsTest"],
                                     RequirementLevel = RequirementLevels.Should,
                                     LocationInDocument = "4.15. Clickjacking"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.AuthEndpoint.HasContentSecurityPolicyTest"],
                                     RequirementLevel = RequirementLevels.Should,
                                     LocationInDocument = "4.15. Clickjacking"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.AuthEndpoint.AutomaticRedirectInvalidScopeTest"],
                                     RequirementLevel = RequirementLevels.Should,
                                     LocationInDocument = "4.17. Authorization Server Redirecting to Phishing Site"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.AuthEndpoint.AutomaticRedirectInvalidResponseTypeTest"],
                                     RequirementLevel = RequirementLevels.Should,
                                     LocationInDocument = "4.17. Authorization Server Redirecting to Phishing Site"
                                 },
                            ]
                        },
                        new OAuthDocument {
                            Id = "OIDC",
                            Name = "OpenID Connect Core 1.0 incorporating errata set 1",
                            Description = "OpenID Connect 1.0 is a simple identity layer on top of the OAuth 2.0 protocol. It enables Clients to verify the identity of the End-User based on the authentication performed by an Authorization Server, as well as to obtain basic profile information about the End-User in an interoperable and REST-like manner. This specification defines the core OpenID Connect functionality: authentication built on top of OAuth 2.0 and the use of Claims to communicate information about the End-User. It also describes the security and privacy considerations for using OpenID Connect.",
                            Url = "https://openid.net/specs/openid-connect-core-1_0.html",
                            IsSupportedTest = "OAuch.Compliance.Tests.DocumentSupport.OpenIdSupportedTest",
                             IsStandard = true,
                             DocumentCategory = DocumentCategories.OpenIDConnect,
                             DeprecatedFeatures  = [],
                             Countermeasures= [
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.IdTokens.HasRequiredClaimsTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "2. ID Token"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.IdTokens.NoncePresentInTokenTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "2. ID Token"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.IdTokens.HasAuthorizedPartyTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "2. ID Token"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.IdTokens.IsSignedTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "2. ID Token"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.IdTokens.KeyReferencesTest"],
                                     RequirementLevel = RequirementLevels.Should,
                                     LocationInDocument = "2. ID Token"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.AuthEndpoint.SupportsPostAuthorizationRequestsTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "3.1.2.1. Authentication Request"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.AuthEndpoint.RedirectUriRequiredTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "3.1.2.1. Authentication Request"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.IsHttpsRequiredTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "3.1.3. Token Endpoint"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.IsClientAuthenticationRequiredTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "3.1.3.1. Token Request"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.IsGetSupportedTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "3.2. Token Endpoint"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.IdTokens.IsAccessTokenHashCorrectTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "3.1.3.6. ID Token"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.IdTokens.HasCorrectIssuerTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "3.1.3.7. ID Token Validation"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.IdTokens.HasCorrectAudienceTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "3.1.3.7. ID Token Validation"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.IdTokens.HasAzpForMultiAudienceTest"],
                                     RequirementLevel = RequirementLevels.Should,
                                     LocationInDocument = "3.1.3.7. ID Token Validation"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.IdTokens.HasCorrectMacTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "3.1.3.7. ID Token Validation"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.IdTokens.ClientSecretLongEnoughTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "16.19. Symmetric Key Entropy"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.AuthEndpoint.NonceRequiredTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "3.2.2.1. Authentication Request"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.IdTokens.IsAccessTokenHashPresentTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "3.2.2.9. Access Token Validation"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.IdTokens.CodeHashValidTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "3.3.2.10. Authorization Code Validationn"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.IdTokens.IsAuthorizationCodeHashPresentTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "3.3.2.11. ID Token"
                                 },
                             ],
                             AdditionalTests = [
                                 Tests["OAuch.Compliance.Tests.Features.CodeIdTokenFlowSupportedTest"],
                                 Tests["OAuch.Compliance.Tests.Features.IdTokenFlowSupportedTest"],
                             ]
                        },
                        new OAuthDocument {
                            Id = "FormPost",
                            Name = "OAuth 2.0 Form Post Response Mode",
                            Description = "This specification defines the Form Post Response Mode. In this mode, Authorization Response parameters are encoded as HTML form values that are auto-submitted in the User Agent, and thus are transmitted via the HTTP POST method to the Client, with the result parameters being encoded in the body using the application/x-www-form-urlencoded format.",
                            Url = "https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html",
                            IsSupportedTest = "OAuch.Compliance.Tests.DocumentSupport.FormPostSupportedTest",
                            IsStandard = true,
                            DocumentCategory = DocumentCategories.OAuth2,
                            DeprecatedFeatures  = [],
                            Countermeasures= [
                                new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.AuthEndpoint.SupportsPostResponseModeTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "2. Form Post Response Mode"
                                }
                            ]
                        },
                        new OAuthDocument {
                            Id = "FAPI1Base",
                            Name = "Financial-grade API Security Profile (FAPI) 1.0 – Part 1: Baseline",
                            Description = "A secured OAuth profile that aims to provide specific implementation guidelines for security and interoperability.",
                            Url = "https://openid.net/specs/openid-financial-api-part-1-1_0.html",
                            IsSupportedTest = "OAuch.Compliance.Tests.DocumentSupport.OpenIdSupportedTest",
                            IsStandard = true,
                            DocumentCategory = DocumentCategories.OpenIDConnect,
                            DeprecatedFeatures  = [
                                 new TestRequirementLevel {
                                    Test = Tests["OAuch.Compliance.Tests.Features.IsDeprecatedTlsSupportedTest"],
                                    RequirementLevel = RequirementLevels.Must,
                                    LocationInDocument = "7.1. TLS and DNSSEC considerations"
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Features.PlainPkceTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "5.2.2. Authorization server"
                                 },

                            ],
                            Countermeasures= [
                                new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.AuthEndpoint.HasValidCertificateTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "7.1. TLS and DNSSEC considerations"
                                },
                                new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.AuthEndpoint.IsHttpsRequiredTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "7.1. TLS and DNSSEC considerations"
                                },
                                new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.AuthEndpoint.IsModernTlsSupportedTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "7.1. TLS and DNSSEC considerations"
                                },
                                new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.HasValidCertificateTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "7.1. TLS and DNSSEC considerations"
                                },
                                new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.IsHttpsRequiredTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "7.1. TLS and DNSSEC considerations"
                                },
                                new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.IsModernTlsSupportedTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "7.1. TLS and DNSSEC considerations"
                                },
                                new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.ApiEndpoint.HasValidCertificateTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "7.1. TLS and DNSSEC considerations"
                                },
                                new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.ApiEndpoint.IsHttpsRequiredTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "7.1. TLS and DNSSEC considerations"
                                },
                                new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.ApiEndpoint.IsModernTlsSupportedTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "7.1. TLS and DNSSEC considerations"
                                },
                                new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Revocation.IsRevocationEndpointSecureTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "7.1. TLS and DNSSEC considerations"
                                },
                                new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Revocation.IsModernTlsSupportedTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "7.1. TLS and DNSSEC considerations"
                                },

                                new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.IdTokens.ClientSecretLongEnoughTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "5.2.2. Authorization server"
                                },
                                new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.IdTokens.SigningKeySecureTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "5.2.2. Authorization server"
                                },
                                new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.ClientKeySecureTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "5.2.2. Authorization server"
                                },
                                new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Pkce.IsPkceRequiredTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "5.2.2. Authorization server"
                                },
                                new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Pkce.HashedPkceDisabledTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "5.2.2. Authorization server"
                                },
                                new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Pkce.IsPkceDowngradeDetectedTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "5.2.2. Authorization server"
                                },
                                new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Pkce.IsPkceTokenDowngradeDetectedTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "5.2.2. Authorization server"
                                },
                                new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Pkce.IsPkcePlainDowngradeDetectedTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "5.2.2. Authorization server"
                                },
                                new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Pkce.ShortVerifierTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "5.2.2. Authorization server"
                                },
                                new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Pkce.PlainPkceDisabledTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "5.2.2. Authorization server"
                                },
                                new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.AuthEndpoint.RedirectUriRequiredTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "5.2.2. Authorization server"
                                },
                                new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.AuthEndpoint.RedirectUriPathMatchedTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "5.2.2. Authorization server"
                                },
                                new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.AuthEndpoint.RedirectUriConfusionTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "5.2.2. Authorization server"
                                },
                                new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.AuthEndpoint.RedirectUriFullyMatchedTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "5.2.2. Authorization server"
                                },
                                new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.AuthEndpoint.CodePollutionTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "5.2.2. Authorization server"
                                },
                                new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.MultipleCodeExchangesTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "5.2.2. Authorization server"
                                },
                                new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Tokens.AuthorizationCodeEntropyMinReqTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "5.2.2. Authorization server"
                                },
                                new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Tokens.AuthorizationCodeEntropySugReqTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "5.2.2. Authorization server"
                                },
                                new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Tokens.RefreshTokenEntropyMinReqTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "5.2.2. Authorization server"
                                },
                                new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Tokens.RefreshTokenEntropySugReqTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "5.2.2. Authorization server"
                                },
                                new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Tokens.AccessTokenEntropyMinReqTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "5.2.2. Authorization server"
                                },
                                new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Tokens.AccessTokenEntropySugReqTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "5.2.2. Authorization server"
                                },
                                new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Tokens.ShortTokenTimeoutTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "5.2.2. Authorization server"
                                },
                                //OAuch.Compliance.Tests.AuthEndpoint.SupportsPostAuthorizationRequestsTest
                            ]
                        },
                        new OAuthDocument {
                            Id = "FAPI1Adv",
                            Name = "Financial-grade API Security Profile (FAPI) 1.0 – Part 2: Advanced",
                            Description = "A highly secured OAuth profile that aims to provide specific implementation guidelines for security and interoperability.",
                            Url = "https://openid.net/specs/openid-financial-api-part-2-1_0.html",
                            IsSupportedTest = "OAuch.Compliance.Tests.DocumentSupport.OpenIdSupportedTest",
                            IsStandard = true,
                            DocumentCategory = DocumentCategories.OpenIDConnect,
                            DeprecatedFeatures  = [
                                 new TestRequirementLevel {
                                    Test = Tests["OAuch.Compliance.Tests.Features.IsDeprecatedTlsSupportedTest"],
                                    RequirementLevel = RequirementLevels.Must,
                                    LocationInDocument = "8.5. TLS considerations"
                                 }
                            ],
                            Countermeasures= [
                                new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.AuthEndpoint.HasValidCertificateTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "8.5. TLS considerations"
                                },
                                new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.AuthEndpoint.IsHttpsRequiredTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "8.5. TLS considerations"
                                },
                                new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.AuthEndpoint.IsModernTlsSupportedTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "8.5. TLS considerations"
                                },
                                new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.HasValidCertificateTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "8.5. TLS considerations"
                                },
                                new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.IsHttpsRequiredTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "8.5. TLS considerations"
                                },
                                new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.IsModernTlsSupportedTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "8.5. TLS considerations"
                                },
                                new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.ApiEndpoint.HasValidCertificateTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "8.5. TLS considerations"
                                },
                                new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.ApiEndpoint.IsHttpsRequiredTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "8.5. TLS considerations"
                                },
                                new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.ApiEndpoint.IsModernTlsSupportedTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "8.5. TLS considerations"
                                },
                                new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Revocation.IsRevocationEndpointSecureTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "8.5. TLS considerations"
                                },
                                new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Revocation.IsModernTlsSupportedTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "8.5. TLS considerations"
                                },
                                new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.AuthEndpoint.AreStrongCiphersEnabledTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "8.5. TLS considerations"
                                },
                                new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.AreStrongCiphersEnabledTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "8.5. TLS considerations"
                                },
                                new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.ApiEndpoint.AreStrongCiphersEnabledTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "8.5. TLS considerations"
                                },
                            ]
                        },
                        new OAuthDocument {
                            Id = "AttsDefs",
                            Name = "OAuth2 Attacks & Defenses",
                            Description = "This document contains a small set of test cases for attacks on OAuth implementations that are not covered by the other documents.",
                            Url = "",
                            IsSupportedTest = "OAuch.Compliance.Tests.DocumentSupport.RFC6749SupportedTest",
                            IsStandard = false,
                            DocumentCategory = DocumentCategories.Other,
                            DeprecatedFeatures  = [],
                             Countermeasures= [
                                 //new TestRequirementLevel {
                                 //    Test  = Tests["OAuch.Compliance.Tests.Debug.DebugTest"],
                                 //    RequirementLevel = RequirementLevels.Must,
                                 //    LocationInDocument = ""
                                 //},
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Jwt.AcceptsNoneSignatureTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = ""
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.MultipleCodeExchangesTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = ""
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Concurrency.SingleFastACExchangeTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = ""
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Concurrency.MultiFastACExchangeTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = ""
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.TokenEndpoint.RefreshTokenRevokedAfterUseTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = ""
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Concurrency.SingleFastRefreshTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = ""
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Concurrency.MultiFastRefreshTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = ""
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Concurrency.ConcurrentTokensRevokedTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = ""
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Revocation.CanAccessTokensBeRevokedTest"],
                                     RequirementLevel = RequirementLevels.Should,
                                     LocationInDocument = ""
                                 },
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Revocation.CanRefreshTokensBeRevokedTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = ""
                                 }
                             ]
                        }
                    ];
                return _documents;
            }
        }
    }
}