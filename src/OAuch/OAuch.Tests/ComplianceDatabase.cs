using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

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
                        var i = Activator.CreateInstance(t) as Test;
                        if (i != null) {
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
                    _testsDictionary = new Dictionary<string, Test>();
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
                if (_threats == null) {
                    _threats = new List<Threat> {
                        new Threat {
                            Id = "6819_4_1_1",
                            Title = "Obtaining Client Secrets",
                            Description = "The attacker could try to get access to the secret of a particular client in order to obtain tokens on behalf of the attacked client with the privileges of that 'client_id' acting as an instance of the client.",
                            Document = Documents["RFC6819"],
                            LocationInDocument = "4.1.1.",
                            Instances = new List<ThreatInstance> {
                                new ThreatInstance {
                                     ExtraDescription = "A malicious client can impersonate another client and obtain access to protected resources if the impersonated client fails to, or is unable to, keep its client credentials confidential.",
                                      DependsOnFeatures = new List<Test>{
                                          Tests["OAuch.Compliance.Tests.Features.TokenFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.IdTokenTokenFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.CodeTokenFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.CodeIdTokenTokenFlowSupportedTest"]
                                      },
                                      MitigatedBy = new List<TestCombination> {
                                          new TestCombination {
                                              Tests["OAuch.Compliance.Tests.AuthEndpoint.RequireUserConsentTest"]
                                          }
                                      }
                                }
                            }
                        },
                        new Threat {
                            Id = "6819_4_1_2",
                            Title = "Obtaining Refresh Tokens",
                            Description = "Depending on the client type, there are different ways that refresh tokens may be revealed to an attacker. An attacker may obtain the refresh tokens issued to a web application by way of overcoming the web server's security controls. On native clients, refresh tokens may be read from the local file system or the device could be stolen or cloned.",
                            Document = Documents["RFC6819"],
                            LocationInDocument = "4.1.2.",
                            Instances = new List<ThreatInstance> {
                                new ThreatInstance {
                                     ExtraDescription = null,
                                      DependsOnFeatures = new List<Test> {
                                          Tests["OAuch.Compliance.Tests.Features.HasRefreshTokensTest"]
                                      },
                                      MitigatedBy = new List<TestCombination> {
                                          new TestCombination {
                                              Tests["OAuch.Compliance.Tests.TokenEndpoint.UsesTokenRotationTest"],
                                              Tests["OAuch.Compliance.Tests.TokenEndpoint.InvalidatedRefreshTokenTest"],                                              
                                              Tests["OAuch.Compliance.Tests.TokenEndpoint.RefreshTokenRevokedAfterUseTest"],
                                              Tests["OAuch.Compliance.Tests.TokenEndpoint.IsRefreshBoundToClientTest"],
                                              Tests["OAuch.Compliance.Tests.TokenEndpoint.IsRefreshAuthenticationRequiredTest"],
                                              Tests["OAuch.Compliance.Tests.Revocation.CanRefreshTokensBeRevokedTest"]
                                          }
                                      }
                                }
                            }
                        },
                        new Threat {
                            Id = "6819_4_1_3",
                            Title = "Obtaining Access Tokens",
                            Description = "Depending on the client type, there are different ways that access tokens may be revealed to an attacker. Access tokens could be stolen from the device if the application stores them in a storage device that is accessible to other applications.",
                            Document = Documents["RFC6819"],
                            LocationInDocument = "4.1.3.",
                            Instances = new List<ThreatInstance> {
                                new ThreatInstance {
                                     ExtraDescription = null,
                                      DependsOnFeatures = new List<Test>{
                                          Tests["OAuch.Compliance.Tests.Features.HasAccessTokensTest"]
                                      },
                                      MitigatedBy = new List<TestCombination> {
                                          new TestCombination {
                                              Tests["OAuch.Compliance.Tests.Tokens.TokenTimeoutTest"]
                                          }
                                      }
                                }
                            }
                        },
                        new Threat {
                            Id = "6819_4_1_5",
                            Title = "Open Redirectors on Client",
                            Description = "An open redirector is an endpoint using a parameter to automatically redirect a user agent to the location specified by the parameter value without any validation.  If the authorization server allows the client to register only part of the redirect URI, an attacker can use an open redirector operated by the client to construct a redirect URI that will pass the authorization server validation but will send the authorization 'code' or access token to an endpoint under the control of the attacker.",
                            Document = Documents["RFC6819"],
                            LocationInDocument = "4.1.5.",
                            Instances = new List<ThreatInstance> {
                                new ThreatInstance {
                                     ExtraDescription = null,
                                      DependsOnFeatures = new List<Test>{
                                          /* Depends on one of the flows that uses the authorization endpoint */
                                          Tests["OAuch.Compliance.Tests.Features.CodeFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.CodeTokenFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.CodeIdTokenFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.CodeIdTokenTokenFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.TokenFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.IdTokenTokenFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.IdTokenFlowSupportedTest"],
                                      },
                                      MitigatedBy = new List<TestCombination> {
                                          new TestCombination {
                                              Tests["OAuch.Compliance.Tests.AuthEndpoint.RedirectUriPathMatchedTest"],
                                              Tests["OAuch.Compliance.Tests.AuthEndpoint.RedirectUriFullyMatchedTest"]
                                          }
                                      }
                                }
                            }
                        },
                        new Threat {
                            Id = "6819_4_2_1",
                            Title = "Password Phishing by Counterfeit Authorization Server",
                            Description = "Auth makes no attempt to verify the authenticity of the authorization server. A hostile party could take advantage of this by intercepting the client's requests and returning misleading or otherwise incorrect responses. This could be achieved using DNS or Address Resolution Protocol (ARP) spoofing.  Wide deployment of OAuth and similar protocols may cause users to become inured to the practice of being redirected to web sites where they are asked to enter their passwords. If users are not careful to verify the authenticity of these web sites before entering their credentials, it will be possible for attackers to exploit this practice to steal users' passwords.",
                            Document = Documents["RFC6819"],
                            LocationInDocument = "4.2.1.",
                            Instances = new List<ThreatInstance> {
                                new ThreatInstance {
                                     ExtraDescription = null,
                                      DependsOnFeatures = new List<Test>{
                                          /* Depends on one of the flows that uses the authorization endpoint */
                                          Tests["OAuch.Compliance.Tests.Features.CodeFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.CodeTokenFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.CodeIdTokenFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.CodeIdTokenTokenFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.TokenFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.IdTokenTokenFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.IdTokenFlowSupportedTest"],
                                      },
                                      MitigatedBy = new List<TestCombination> {
                                          new TestCombination {
                                              Tests["OAuch.Compliance.Tests.AuthEndpoint.HasValidCertificateTest"],
                                              Tests["OAuch.Compliance.Tests.AuthEndpoint.IsHttpsRequiredTest"],
                                              Tests["OAuch.Compliance.Tests.AuthEndpoint.IsModernTlsSupportedTest"],
                                          }

                                      }
                                }
                            }
                        },
                        new Threat {
                            Id = "6819_4_2_3",
                            Title = "Malicious Client Obtains Existing Authorization by Fraud",
                            Description = "Authorization servers may wish to automatically process authorization requests from clients that have been previously authorized by the user. When the user is redirected to the authorization server's end-user authorization endpoint to grant access, the authorization server detects that the user has already granted access to that particular client. Instead of prompting the user for approval, the authorization server automatically redirects the user back to the client. A malicious client may exploit that feature and try to obtain such an authorization 'code' instead of the legitimate client.",
                            Document = Documents["RFC6819"],
                            LocationInDocument = "4.2.3",
                            Instances = new List<ThreatInstance> {
                                new ThreatInstance {
                                     ExtraDescription = null,
                                      DependsOnFeatures = new List<Test>{
                                          /* Depends on one of the flows that uses the authorization endpoint */
                                          Tests["OAuch.Compliance.Tests.Features.CodeFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.CodeTokenFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.CodeIdTokenFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.CodeIdTokenTokenFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.TokenFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.IdTokenTokenFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.IdTokenFlowSupportedTest"],
                                      },
                                      MitigatedBy = new List<TestCombination> {
                                          new TestCombination {
                                              Tests["OAuch.Compliance.Tests.AuthEndpoint.RequireUserConsentTest"]
                                          },
                                          new TestCombination {
                                              Tests["OAuch.Compliance.Tests.AuthEndpoint.RedirectUriPathMatchedTest"],
                                              Tests["OAuch.Compliance.Tests.AuthEndpoint.RedirectUriFullyMatchedTest"]
                                          }
                                      }
                                }
                            }
                        },
                        new Threat {
                            Id = "6819_4_2_4",
                            Title = "Open Redirector",
                            Description = "An attacker could use the end-user authorization endpoint and the redirect URI parameter to abuse the authorization server as an open redirector. An open redirector is an endpoint using a parameter to automatically redirect a user agent to the location specified by the parameter value without any validation. An attacker could utilize a user's trust in an authorization server to launch a phishing attack.",
                            Document = Documents["RFC6819"],
                            LocationInDocument = "4.2.4",
                            Instances = new List<ThreatInstance> {
                                new ThreatInstance {
                                     ExtraDescription = null,
                                      DependsOnFeatures = new List<Test>{
                                          /* Depends on one of the flows that uses the authorization endpoint */
                                          Tests["OAuch.Compliance.Tests.Features.CodeFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.CodeTokenFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.CodeIdTokenFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.CodeIdTokenTokenFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.TokenFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.IdTokenTokenFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.IdTokenFlowSupportedTest"],
                                      },
                                      MitigatedBy = new List<TestCombination> {
                                          new TestCombination {
                                              Tests["OAuch.Compliance.Tests.AuthEndpoint.RedirectUriPathMatchedTest"],
                                              Tests["OAuch.Compliance.Tests.AuthEndpoint.RedirectUriFullyMatchedTest"],
                                              Tests["OAuch.Compliance.Tests.AuthEndpoint.InvalidRedirectTest"] // BCP 4.10.2
                                          }
                                      }
                                }
                            }
                        },
                        new Threat {
                            Id = "6819_4_3_1",
                            Title = "Eavesdropping Access Tokens in Transit",
                            Description = "Attackers may attempt to eavesdrop access tokens in transit from the authorization server to the client.",
                            Document = Documents["RFC6819"],
                            LocationInDocument = "4.3.1.",
                            Instances = new List<ThreatInstance> {
                                new ThreatInstance {
                                     ExtraDescription = null,
                                      DependsOnFeatures = new List<Test>{
                                          Tests["OAuch.Compliance.Tests.Features.HasSupportedFlowsTest"]
                                      },
                                      MitigatedBy = new List<TestCombination> {
                                          new TestCombination {
                                              Tests["OAuch.Compliance.Tests.TokenEndpoint.HasValidCertificateTest"],
                                              Tests["OAuch.Compliance.Tests.TokenEndpoint.IsModernTlsSupportedTest"],
                                              Tests["OAuch.Compliance.Tests.TokenEndpoint.IsHttpsRequiredTest"],
                                              Tests["OAuch.Compliance.Tests.Revocation.IsModernTlsSupportedTest"],
                                              Tests["OAuch.Compliance.Tests.Revocation.IsRevocationEndpointSecureTest"],
                                              Tests["OAuch.Compliance.Tests.DeviceAuthEndpoint.HasValidCertificateTest"],
                                              Tests["OAuch.Compliance.Tests.DeviceAuthEndpoint.IsHttpsRequiredTest"],
                                              Tests["OAuch.Compliance.Tests.DeviceAuthEndpoint.IsModernTlsSupportedTest"],
                                          }
                                      }
                                }
                            }
                        },
                        new Threat {
                            Id = "6819_4_3_3",
                            Title = "Disclosure of Client Credentials during Transmission",
                            Description = "An attacker could attempt to eavesdrop the transmission of client credentials between the client and server during the client authentication process or during OAuth token requests.",
                            Document = Documents["RFC6819"],
                            LocationInDocument = "4.3.3.",
                            Instances = new List<ThreatInstance> {
                                new ThreatInstance {
                                     ExtraDescription = null,
                                      DependsOnFeatures = new List<Test>{
                                          Tests["OAuch.Compliance.Tests.Features.HasSupportedFlowsTest"]
                                      },
                                      MitigatedBy = new List<TestCombination> {
                                          new TestCombination {
                                              Tests["OAuch.Compliance.Tests.TokenEndpoint.HasValidCertificateTest"],
                                              Tests["OAuch.Compliance.Tests.TokenEndpoint.IsModernTlsSupportedTest"],
                                              Tests["OAuch.Compliance.Tests.TokenEndpoint.IsHttpsRequiredTest"]
                                          },
                                          new TestCombination {
                                              Tests["OAuch.Compliance.Tests.TokenEndpoint.IsAsymmetricClientAuthenticationUsedTest"]
                                          }
                                      }
                                }
                            }
                        },
                        new Threat {
                            Id = "6819_4_3_5",
                            Title = "Obtaining Client Secret by Online Guessing",
                            Description = "An attacker may try to guess valid 'client_id'/secret pairs.",
                            Document = Documents["RFC6819"],
                            LocationInDocument = "4.3.5.",
                            Instances = new List<ThreatInstance> {
                                new ThreatInstance {
                                     ExtraDescription = null,
                                      DependsOnFeatures = new List<Test>{
                                          /* Depends on one of the flows that uses the token endpoint */
                                          Tests["OAuch.Compliance.Tests.Features.CodeFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.CodeTokenFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.CodeIdTokenFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.CodeIdTokenTokenFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.ClientCredentialsFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.DeviceFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.PasswordFlowSupportedTest"]
                                      },
                                      MitigatedBy = new List<TestCombination> {
                                          new TestCombination {
                                              Tests["OAuch.Compliance.Tests.TokenEndpoint.ClientSecretEntropyMinReqTest"],
                                              Tests["OAuch.Compliance.Tests.TokenEndpoint.ClientSecretEntropySugReqTest"]
                                          },
                                          new TestCombination {
                                              Tests["OAuch.Compliance.Tests.TokenEndpoint.IsAsymmetricClientAuthenticationUsedTest"]
                                          }
                                      }
                                }
                            }
                        },
                        new Threat {
                            Id = "6819_4_4_1_1",
                            Title = "Eavesdropping or Leaking Authorization 'codes'",
                            Description = "An attacker could try to eavesdrop transmission of the authorization 'code' between the authorization server and client. Furthermore, authorization 'codes' are passed via the browser, which may unintentionally leak those codes to untrusted web sites and attackers in different ways.",
                            Document = Documents["RFC6819"],
                            LocationInDocument = "4.4.1.1.",
                            Instances = new List<ThreatInstance> {
                                new ThreatInstance {
                                     ExtraDescription = null,
                                      DependsOnFeatures = new List<Test>{
                                          /* Depends on one of the flows that uses authorization codes */
                                          Tests["OAuch.Compliance.Tests.Features.CodeFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.CodeTokenFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.CodeIdTokenFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.CodeIdTokenTokenFlowSupportedTest"],
                                      },
                                      MitigatedBy = new List<TestCombination> {
                                          new TestCombination {
                                              Tests["OAuch.Compliance.Tests.TokenEndpoint.IsCodeBoundToClientTest"],
                                              Tests["OAuch.Compliance.Tests.TokenEndpoint.AuthorizationCodeTimeoutTest"],
                                              Tests["OAuch.Compliance.Tests.TokenEndpoint.MultipleCodeExchangesTest"],
                                              Tests["OAuch.Compliance.Tests.TokenEndpoint.TokenValidAfterMultiExchangeTest"]
                                          }
                                      }
                                }
                            }
                        },
                        new Threat {
                            Id = "6819_4_4_1_3",
                            Title = "Online Guessing of Authorization 'codes'",
                            Description = "An attacker may try to guess valid authorization 'code' values and send the guessed code value using the grant type 'code' in order to obtain a valid access token.",
                            Document = Documents["RFC6819"],
                            LocationInDocument = "4.4.1.3.",
                            Instances = new List<ThreatInstance> {
                                new ThreatInstance {
                                     ExtraDescription = null,
                                      DependsOnFeatures = new List<Test>{
                                          /* Depends on one of the flows that uses authorization codes */
                                          Tests["OAuch.Compliance.Tests.Features.CodeFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.CodeTokenFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.CodeIdTokenFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.CodeIdTokenTokenFlowSupportedTest"],
                                      },
                                      MitigatedBy = new List<TestCombination> {
                                          new TestCombination {
                                              Tests["OAuch.Compliance.Tests.Tokens.AuthorizationCodeEntropyMinReqTest"],
                                              Tests["OAuch.Compliance.Tests.Tokens.AuthorizationCodeEntropySugReqTest"],
                                              Tests["OAuch.Compliance.Tests.TokenEndpoint.AuthorizationCodeTimeoutTest"],
                                              Tests["OAuch.Compliance.Tests.TokenEndpoint.IsCodeBoundToClientTest"],
                                              Tests["OAuch.Compliance.Tests.TokenEndpoint.IsClientAuthenticationRequiredTest"],
                                              Tests["OAuch.Compliance.Tests.TokenEndpoint.RedirectUriCheckedTest"]
                                          }
                                      }
                                }
                            }
                        },
                        new Threat {
                            Id = "6819_4_4_1_5",
                            Title = "Authorization 'code' Phishing",
                            Description = "A hostile party could impersonate the client site and get access to the authorization 'code'. This could be achieved using DNS or ARP spoofing. This applies to clients, which are web applications; thus, the redirect URI is not local to the host where the user's browser is running.",
                            Document = Documents["RFC6819"],
                            LocationInDocument = "4.4.1.5.",
                            Instances = new List<ThreatInstance> {
                                new ThreatInstance {
                                     ExtraDescription = null,
                                      DependsOnFeatures = new List<Test>{
                                          /* Depends on one of the flows that uses authorization codes */
                                          Tests["OAuch.Compliance.Tests.Features.CodeFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.CodeTokenFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.CodeIdTokenFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.CodeIdTokenTokenFlowSupportedTest"],
                                      },
                                      MitigatedBy = new List<TestCombination> {
                                          new TestCombination {
                                              Tests["OAuch.Compliance.Tests.TokenEndpoint.IsCodeBoundToClientTest"],
                                              Tests["OAuch.Compliance.Tests.TokenEndpoint.IsClientAuthenticationRequiredTest"]
                                          }
                                      }
                                }
                            }
                        },
                        new Threat {
                            Id = "6819_4_4_1_7",
                            Title = "Authorization 'code' Leakage through Counterfeit Client",
                            Description = "The attacker leverages the authorization 'code' grant type in an attempt to get another user (victim) to log in, authorize access to his/her resources, and subsequently obtain the authorization 'code' and inject it into a client application using the attacker's account. The goal is to associate an access authorization for resources of the victim with the user account of the attacker on a client site. The attacker abuses an existing client application and combines it with his own counterfeit client web site.  The attacker depends on the victim expecting the client application to request access to a certain resource server.  The victim, seeing only a normal request from an expected application, approves the request.  The attacker then uses the victim's authorization to gain access to the information unknowingly authorized by the victim.",
                            Document = Documents["RFC6819"],
                            LocationInDocument = "4.4.1.7.",
                            Instances = new List<ThreatInstance> {
                                new ThreatInstance {
                                     ExtraDescription = null,
                                      DependsOnFeatures = new List<Test>{
                                          /* Depends on one of the flows that uses authorization codes */
                                          Tests["OAuch.Compliance.Tests.Features.CodeFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.CodeTokenFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.CodeIdTokenFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.CodeIdTokenTokenFlowSupportedTest"],
                                      },
                                      MitigatedBy = new List<TestCombination> {
                                          new TestCombination {
                                              Tests["OAuch.Compliance.Tests.AuthEndpoint.RedirectUriPathMatchedTest"],
                                              Tests["OAuch.Compliance.Tests.AuthEndpoint.RedirectUriFullyMatchedTest"],
                                              Tests["OAuch.Compliance.Tests.TokenEndpoint.RedirectUriCheckedTest"]
                                          }
                                      }
                                }
                            }
                        },
                        new Threat {
                            Id = "6819_4_4_1_8",
                            Title = "CSRF Attack against redirect-uri",
                            Description = "Cross-site request forgery (CSRF) is a web-based attack whereby HTTP requests are transmitted from a user that the web site trusts or has authenticated. CSRF attacks on OAuth approvals can allow an attacker to obtain authorization to OAuth protected resources without the consent of the user.",
                            Document = Documents["SecBCP"],
                            LocationInDocument = "4.4.1.8.",
                            Instances = new List<ThreatInstance> {
                                new ThreatInstance {
                                     ExtraDescription = null,
                                      DependsOnFeatures = new List<Test>{
                                          Tests["OAuch.Compliance.Tests.Features.CodeFlowSupportedTest"],
                                      },
                                      MitigatedBy = new List<TestCombination> {
                                          new TestCombination {
                                            Tests["OAuch.Compliance.Tests.Pkce.IsPkceImplementedTest"]
                                          },
                                          new TestCombination {
                                            Tests["OAuch.Compliance.Tests.IdTokens.NoncePresentInTokenTest"]
                                          },
                                          new TestCombination {
                                            Tests["OAuch.Compliance.Tests.AuthEndpoint.StatePresentTest"]
                                          }
                                      }
                                }
                            }
                        },
                        new Threat {
                            Id = "6819_4_4_1_9",
                            Title = "Clickjacking Attack against Authorization",
                            Description = "With clickjacking, a malicious site loads the target site in a transparent iFrame overlaid on top of a set of dummy buttons that are carefully constructed to be placed directly under important buttons on the target site.  When a user clicks a visible button, they are actually clicking a button (such as an 'Authorize' button) on the hidden page.",
                            Document = Documents["RFC6819"],
                            LocationInDocument = "4.4.1.9.",
                            Instances = new List<ThreatInstance> {
                                new ThreatInstance {
                                     ExtraDescription = null,
                                      DependsOnFeatures = new List<Test>{
                                          /* Depends on one of the flows that uses the authorization endpoint */
                                          Tests["OAuch.Compliance.Tests.Features.CodeFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.CodeTokenFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.CodeIdTokenFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.CodeIdTokenTokenFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.TokenFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.IdTokenTokenFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.IdTokenFlowSupportedTest"],
                                      },
                                      MitigatedBy = new List<TestCombination> {
                                          new TestCombination {
                                              Tests["OAuch.Compliance.Tests.AuthEndpoint.HasFrameOptionsTest"],
                                              Tests["OAuch.Compliance.Tests.AuthEndpoint.HasContentSecurityPolicyTest"]
                                          }
                                      }
                                }
                            }
                        },
                        new Threat {
                            Id = "6819_4_4_1_13",
                            Title = "Code Substitution (OAuth Login)",
                            Description = "An attacker could attempt to log into an application or web site using a victim's identity. Applications relying on identity data provided by an OAuth protected service API to login users are vulnerable to this threat. This pattern can be found in so-called 'social login' scenarios.",
                            Document = Documents["RFC6819"],
                            LocationInDocument = "4.4.1.13.",
                            Instances = new List<ThreatInstance> {
                                new ThreatInstance {
                                     ExtraDescription = null,
                                      DependsOnFeatures = new List<Test>{
                                          Tests["OAuch.Compliance.Tests.DocumentSupport.OpenIdSupportedTest"]
                                      },
                                      MitigatedBy = new List<TestCombination> {
                                          new TestCombination {
                                              Tests["OAuch.Compliance.Tests.TokenEndpoint.IsCodeBoundToClientTest"],
                                              Tests["OAuch.Compliance.Tests.TokenEndpoint.IsClientAuthenticationRequiredTest"]
                                          }
                                      }
                                }
                            }
                        },
                        new Threat {
                            Id = "6819_4_4_2_2",
                            Title = "Access Token Leak in Browser History",
                            Description = "An attacker could obtain the token from the browser's history. Note that this means the attacker needs access to the particular device.",
                            Document = Documents["RFC6819"],
                            LocationInDocument = "4.4.2.2.",
                            Instances = new List<ThreatInstance> {
                                new ThreatInstance {
                                     ExtraDescription = null,
                                      DependsOnFeatures = new List<Test>{
                                          Tests["OAuch.Compliance.Tests.Features.TokenFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.IdTokenTokenFlowSupportedTest"],
                                      },
                                      MitigatedBy = new List<TestCombination> {
                                          new TestCombination {
                                              Tests["OAuch.Compliance.Tests.Tokens.TokenTimeoutTest"],
                                              Tests["OAuch.Compliance.Tests.TokenEndpoint.HasCacheControlHeaderTest"],
                                              Tests["OAuch.Compliance.Tests.TokenEndpoint.HasPragmaHeaderTest"],
                                              Tests["OAuch.Compliance.Tests.AuthEndpoint.SupportsPostResponseModeTest"], // from BCP 4.3.2
                                              Tests["OAuch.Compliance.Tests.ApiEndpoint.TokenAsQueryParameterDisabledTest"] // from BCP 4.3.2
                                          }
                                      }
                                }
                            }
                        },
                        new Threat {
                            Id = "6819_4_4_3_1",
                            Title = "Accidental Exposure of Passwords at Client Site",
                            Description = "If the client does not provide enough protection, an attacker or disgruntled employee could retrieve the passwords for a user.",
                            Document = Documents["RFC6819"],
                            LocationInDocument = "4.4.3.1.",
                            Instances = new List<ThreatInstance> {
                                new ThreatInstance {
                                     ExtraDescription = null,
                                      DependsOnFeatures = new List<Test>{
                                            Tests["OAuch.Compliance.Tests.Features.PasswordFlowSupportedTest"]
                                      },
                                      MitigatedBy = new List<TestCombination> {
                                          new TestCombination {
                                            Tests["OAuch.Compliance.Tests.TokenEndpoint.IsPasswordFlowDisabledTest"]
                                          }
                                      }
                                }
                            }
                        },
                        new Threat {
                            Id = "6819_4_4_3_2",
                            Title = "Client Obtains Scopes without End-User Authorization",
                            Description = "All interaction with the resource owner is performed by the client. Thus it might, intentionally or unintentionally, happen that the client obtains a token with scope unknown for, or unintended by, the resource owner.  For example, the resource owner might think the client needs and acquires read-only access to its media storage only but the client tries to acquire an access token with full access permissions.",
                            Document = Documents["RFC6819"],
                            LocationInDocument = "4.4.3.2.",
                            Instances = new List<ThreatInstance> {
                                new ThreatInstance {
                                     ExtraDescription = null,
                                      DependsOnFeatures = new List<Test>{
                                            Tests["OAuch.Compliance.Tests.Features.PasswordFlowSupportedTest"]
                                      },
                                      MitigatedBy = new List<TestCombination> {
                                          new TestCombination {
                                            Tests["OAuch.Compliance.Tests.TokenEndpoint.IsPasswordFlowDisabledTest"]
                                          }
                                      }
                                }
                            }
                        },
                        new Threat {
                            Id = "6819_4_4_3_3",
                            Title = "Client Obtains Refresh Token through Automatic Authorization",
                            Description = "All interaction with the resource owner is performed by the client. Thus it might, intentionally or unintentionally, happen that the client obtains a long-term authorization represented by a refresh token even if the resource owner did not intend so.",
                            Document = Documents["RFC6819"],
                            LocationInDocument = "4.4.3.3.",
                            Instances = new List<ThreatInstance> {
                                new ThreatInstance {
                                     ExtraDescription = null,
                                      DependsOnFeatures = new List<Test>{
                                            Tests["OAuch.Compliance.Tests.Features.PasswordFlowSupportedTest"]
                                      },
                                      MitigatedBy = new List<TestCombination> {
                                          new TestCombination {
                                            Tests["OAuch.Compliance.Tests.TokenEndpoint.IsPasswordFlowDisabledTest"]
                                          }
                                      }
                                }
                            }
                        },
                        new Threat {
                            Id = "6819_4_4_3_4",
                            Title = "Obtaining User Passwords on Transport",
                            Description = "An attacker could attempt to eavesdrop the transmission of end-user credentials with the grant type 'password' between the client and server.",
                            Document = Documents["RFC6819"],
                            LocationInDocument = "4.4.3.4.",
                            Instances = new List<ThreatInstance> {
                                new ThreatInstance {
                                     ExtraDescription = null,
                                      DependsOnFeatures = new List<Test>{
                                            Tests["OAuch.Compliance.Tests.Features.PasswordFlowSupportedTest"]
                                      },
                                      MitigatedBy = new List<TestCombination> {
                                          new TestCombination {
                                              Tests["OAuch.Compliance.Tests.TokenEndpoint.HasValidCertificateTest"],
                                              Tests["OAuch.Compliance.Tests.TokenEndpoint.IsHttpsRequiredTest"],
                                              Tests["OAuch.Compliance.Tests.TokenEndpoint.IsModernTlsSupportedTest"],
                                          }
                                      }
                                }
                            }
                        },
                        new Threat {
                            Id = "6819_4_5_1",
                            Title = "Eavesdropping Refresh Tokens from Authorization Server",
                            Description = "An attacker may eavesdrop refresh tokens when they are transmitted between the authorization server and the client.",
                            Document = Documents["RFC6819"],
                            LocationInDocument = "4.5.1.",
                            Instances = new List<ThreatInstance> {
                                new ThreatInstance {
                                     ExtraDescription = null,
                                      DependsOnFeatures = new List<Test>{
                                            Tests["OAuch.Compliance.Tests.Features.HasRefreshTokensTest"]
                                      },
                                      MitigatedBy = new List<TestCombination> {
                                          new TestCombination {
                                              Tests["OAuch.Compliance.Tests.TokenEndpoint.HasValidCertificateTest"],
                                              Tests["OAuch.Compliance.Tests.TokenEndpoint.IsModernTlsSupportedTest"],
                                              Tests["OAuch.Compliance.Tests.TokenEndpoint.IsHttpsRequiredTest"],
                                          }
                                      }
                                }
                            }
                        },
                        new Threat {
                            Id = "6819_4_5_2",
                            Title = "Obtaining Refresh Token from Authorization Server Database",
                            Description = "This threat is applicable if the authorization server stores refresh tokens as handles in a database.  An attacker may obtain refresh tokens from the authorization server's database by gaining access to the database or launching a SQL injection attack.",
                            Document = Documents["RFC6819"],
                            LocationInDocument = "4.5.2.",
                            Instances = new List<ThreatInstance> {
                                new ThreatInstance {
                                     ExtraDescription = null,
                                      DependsOnFeatures = new List<Test>{
                                            Tests["OAuch.Compliance.Tests.Features.HasRefreshTokensTest"]
                                      },
                                      MitigatedBy = new List<TestCombination> {
                                          new TestCombination {
                                              Tests["OAuch.Compliance.Tests.TokenEndpoint.IsRefreshBoundToClientTest"],
                                              Tests["OAuch.Compliance.Tests.TokenEndpoint.IsRefreshAuthenticationRequiredTest"],
                                          }
                                      }
                                }
                            }
                        },
                        new Threat {
                            Id = "6819_4_5_3",
                            Title = "Obtaining Refresh Token by Online Guessing",
                            Description = "An attacker may try to guess valid refresh token values and send it using the grant type 'refresh_token' in order to obtain a valid access token.",
                            Document = Documents["RFC6819"],
                            LocationInDocument = "4.5.3.",
                            Instances = new List<ThreatInstance> {
                                new ThreatInstance {
                                     ExtraDescription = null,
                                      DependsOnFeatures = new List<Test>{
                                            Tests["OAuch.Compliance.Tests.Features.HasRefreshTokensTest"]
                                      },
                                      MitigatedBy = new List<TestCombination> {
                                          new TestCombination {
                                              Tests["OAuch.Compliance.Tests.Tokens.RefreshTokenEntropyMinReqTest"],
                                              Tests["OAuch.Compliance.Tests.Tokens.RefreshTokenEntropySugReqTest"],
                                              Tests["OAuch.Compliance.Tests.TokenEndpoint.IsRefreshBoundToClientTest"],
                                              Tests["OAuch.Compliance.Tests.TokenEndpoint.IsRefreshAuthenticationRequiredTest"],
                                          }
                                      }
                                }
                            }
                        },
                        new Threat {
                            Id = "6819_4_5_4",
                            Title = "Refresh Token Phishing by Counterfeit Authorization Server",
                            Description = "An attacker could try to obtain valid refresh tokens by proxying requests to the authorization server.  Given the assumption that the authorization server URL is well-known at development time or can at least be obtained from a well-known resource server, the attacker must utilize some kind of spoofing in order to succeed.",
                            Document = Documents["RFC6819"],
                            LocationInDocument = "4.5.4.",
                            Instances = new List<ThreatInstance> {
                                new ThreatInstance {
                                     ExtraDescription = null,
                                      DependsOnFeatures = new List<Test>{
                                            Tests["OAuch.Compliance.Tests.Features.HasRefreshTokensTest"]
                                      },
                                      MitigatedBy = new List<TestCombination> {
                                          new TestCombination {
                                              Tests["OAuch.Compliance.Tests.TokenEndpoint.HasValidCertificateTest"],
                                          }
                                      }
                                }
                            }
                        },
                        new Threat {
                            Id = "6819_4_6_1",
                            Title = "Eavesdropping Access Tokens on Transport",
                            Description = "An attacker could try to obtain a valid access token on transport between the client and resource server.  As access tokens are shared secrets between the authorization server and resource server, they should be treated with the same care as other credentials (e.g., end-user passwords).",
                            Document = Documents["RFC6819"],
                            LocationInDocument = "4.6.1.",
                            Instances = new List<ThreatInstance> {
                                new ThreatInstance {
                                     ExtraDescription = null,
                                      DependsOnFeatures = new List<Test>{
                                          Tests["OAuch.Compliance.Tests.Features.TestUriSupportedTest"]
                                      },
                                      MitigatedBy = new List<TestCombination> {
                                          new TestCombination {
                                              Tests["OAuch.Compliance.Tests.ApiEndpoint.HasValidCertificateTest"],
                                              Tests["OAuch.Compliance.Tests.ApiEndpoint.IsModernTlsSupportedTest"],
                                              Tests["OAuch.Compliance.Tests.ApiEndpoint.IsHttpsRequiredTest"],
                                              Tests["OAuch.Compliance.Tests.Tokens.TokenTimeoutTest"],
                                          }
                                      }
                                }
                            }
                        },
                        new Threat {
                            Id = "6819_4_6_2",
                            Title = "Replay of Authorized Resource Server Requests",
                            Description = "An attacker could attempt to replay valid requests in order to obtain or to modify/destroy user data.",
                            Document = Documents["RFC6819"],
                            LocationInDocument = "4.6.2.",
                            Instances = new List<ThreatInstance> {
                                new ThreatInstance {
                                     ExtraDescription = null,
                                      DependsOnFeatures = new List<Test>{
                                          Tests["OAuch.Compliance.Tests.Features.TestUriSupportedTest"]
                                      },
                                      MitigatedBy = new List<TestCombination> {
                                          new TestCombination {
                                              Tests["OAuch.Compliance.Tests.ApiEndpoint.HasValidCertificateTest"],
                                              Tests["OAuch.Compliance.Tests.ApiEndpoint.IsModernTlsSupportedTest"],
                                              Tests["OAuch.Compliance.Tests.ApiEndpoint.IsHttpsRequiredTest"],
                                          }
                                      }
                                }
                            }
                        },
                        new Threat {
                            Id = "6819_4_6_3",
                            Title = "Guessing Access Tokens",
                            Description = "Where the token is a handle, the attacker may attempt to guess the access token values based on knowledge they have from other access tokens.",
                            Document = Documents["RFC6819"],
                            LocationInDocument = "4.6.3.",
                            Instances = new List<ThreatInstance> {
                                new ThreatInstance {
                                     ExtraDescription = null,
                                      DependsOnFeatures = new List<Test>{
                                          Tests["OAuch.Compliance.Tests.Features.TestUriSupportedTest"]
                                      },
                                      MitigatedBy = new List<TestCombination> {
                                          new TestCombination {
                                              Tests["OAuch.Compliance.Tests.Tokens.TokenTimeoutTest"],
                                              Tests["OAuch.Compliance.Tests.Tokens.AccessTokenEntropyMinReqTest"],
                                              Tests["OAuch.Compliance.Tests.Tokens.AccessTokenEntropySugReqTest"]
                                          }
                                      }
                                }
                            }
                        },
                        new Threat {
                            Id = "6819_4_6_6",
                            Title = "Leak of Confidential Data in HTTP Proxies",
                            Description = "An OAuth HTTP authentication scheme as discussed in RFC6749 is optional.  However, RFC2616 relies on the Authorization and WWW-Authenticate headers to distinguish authenticated content so that it can be protected.  Proxies and caches, in particular, may fail to adequately protect requests not using these headers.  For example, private authenticated content may be stored in (and thus be retrievable from) publicly accessible caches.",
                            Document = Documents["RFC6819"],
                            LocationInDocument = "4.6.6.",
                            Instances = new List<ThreatInstance> {
                                new ThreatInstance {
                                     ExtraDescription = null,
                                      DependsOnFeatures = new List<Test>{
                                          /* Depends on one of the flows that uses the token endpoint */
                                          Tests["OAuch.Compliance.Tests.Features.CodeFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.CodeTokenFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.CodeIdTokenFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.CodeIdTokenTokenFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.ClientCredentialsFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.DeviceFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.PasswordFlowSupportedTest"]
                                      },
                                      MitigatedBy = new List<TestCombination> {
                                          new TestCombination {
                                              Tests["OAuch.Compliance.Tests.TokenEndpoint.HasCacheControlHeaderTest"],
                                              Tests["OAuch.Compliance.Tests.TokenEndpoint.HasPragmaHeaderTest"]
                                          }
                                      }
                                }
                            }
                        },
                        new Threat {
                            Id = "6819_4_6_7",
                            Title = "Token Leakage via Log Files and HTTP Referrers",
                            Description = "If access tokens are sent via URI query parameters, such tokens may leak to log files and the HTTP 'referer'.",
                            Document = Documents["RFC6819"],
                            LocationInDocument = "4.6.7.",
                            Instances = new List<ThreatInstance> {
                                new ThreatInstance {
                                     ExtraDescription = null,
                                      DependsOnFeatures = new List<Test>{
                                          Tests["OAuch.Compliance.Tests.Features.TestUriSupportedTest"]
                                      },
                                      MitigatedBy = new List<TestCombination> {
                                          new TestCombination {
                                              Tests["OAuch.Compliance.Tests.ApiEndpoint.TokenAsQueryParameterDisabledTest"]
                                          }
                                      }
                                }
                            }
                        },
                        new Threat {
                            Id = "BCP_4_1_2",
                            Title = "Redirect URI Validation Attacks on Implicit Grant",
                            Description = "Implicit clients can be subject to an attack that utilizes the fact that user agents re-attach fragments to the destination URL of a redirect if the location header does not contain a fragment. This allows circumvention even of very narrow redirect URI patterns, but not strict URL matching.",
                            Document = Documents["SecBCP"],
                            LocationInDocument = "4.1.2.",
                            Instances = new List<ThreatInstance> {
                                new ThreatInstance {
                                     ExtraDescription = null,
                                      DependsOnFeatures = new List<Test>{
                                          Tests["OAuch.Compliance.Tests.Features.TokenFlowSupportedTest"],
                                      },
                                      MitigatedBy = new List<TestCombination> {
                                          new TestCombination {
                                              Tests["OAuch.Compliance.Tests.AuthEndpoint.RedirectUriFullyMatchedTest"]
                                          },
                                          new TestCombination {
                                              Tests["OAuch.Compliance.Tests.AuthEndpoint.RedirectUriPathMatchedTest"],
                                              Tests["OAuch.Compliance.Tests.AuthEndpoint.FragmentFixTest"]
                                          }
                                      }
                                }
                            }
                        },
                        new Threat {
                            Id = "BCP_4_2_2",
                            Title = "Leakage from the Authorization Server ",
                            Description = "An attacker can learn 'state' from the authorization request if the authorization endpoint at the authorization server contains links or third-party content.",
                            Document = Documents["SecBCP"],
                            LocationInDocument = "4.2.2.",
                            Instances = new List<ThreatInstance> {
                                new ThreatInstance {
                                     ExtraDescription = null,
                                      DependsOnFeatures = new List<Test>{
                                          /* Depends on one of the flows that uses the authorization endpoint */
                                          Tests["OAuch.Compliance.Tests.Features.CodeFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.CodeTokenFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.CodeIdTokenFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.CodeIdTokenTokenFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.TokenFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.IdTokenTokenFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.IdTokenFlowSupportedTest"],
                                      },
                                      MitigatedBy = new List<TestCombination> {
                                          new TestCombination {
                                              Tests["OAuch.Compliance.Tests.TokenEndpoint.IsCodeBoundToClientTest"],
                                              Tests["OAuch.Compliance.Tests.TokenEndpoint.MultipleCodeExchangesTest"],
                                              Tests["OAuch.Compliance.Tests.TokenEndpoint.TokenValidAfterMultiExchangeTest"],
                                          },
                                          new TestCombination {
                                              Tests["OAuch.Compliance.Tests.AuthEndpoint.ReferrerPolicyEnforcedTest"],
                                          },
                                          new TestCombination {
                                              Tests["OAuch.Compliance.Tests.AuthEndpoint.SupportsPostResponseModeTest"],
                                          }
                                    }
                                }
                            }
                        },
                        new Threat {
                            Id = "BCP_4_3_1",
                            Title = "Authorization Code in Browser History",
                            Description = "When a browser navigates to 'client.example/redirection_endpoint?code=abcd' as a result of a redirect from a provider's authorization endpoint, the URL including the authorization code may end up in the browser's history.  An attacker with access to the device could obtain the code and try to replay it.",
                            Document = Documents["SecBCP"],
                            LocationInDocument = "4.3.1.",
                            Instances = new List<ThreatInstance> {
                                new ThreatInstance {
                                     ExtraDescription = null,
                                      DependsOnFeatures = new List<Test>{
                                          /* Depends on one of the flows that use authorization codes */
                                          Tests["OAuch.Compliance.Tests.Features.CodeFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.CodeTokenFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.CodeIdTokenFlowSupportedTest"],
                                          Tests["OAuch.Compliance.Tests.Features.CodeIdTokenTokenFlowSupportedTest"],
                                      },
                                      MitigatedBy = new List<TestCombination> {
                                          new TestCombination {
                                              Tests["OAuch.Compliance.Tests.TokenEndpoint.MultipleCodeExchangesTest"]
                                          },
                                          new TestCombination {
                                              Tests["OAuch.Compliance.Tests.AuthEndpoint.SupportsPostResponseModeTest"]
                                          }
                                      }
                                }
                            }
                        },
                        new Threat {
                            Id = "BCP_4_5",
                            Title = "Authorization Code Injection",
                            Description = "In an authorization code injection attack, the attacker attempts to inject a stolen authorization code into the attacker's own session with the client. The aim is to associate the attacker's session at the client with the victim's resources or identity.",
                            Document = Documents["SecBCP"],
                            LocationInDocument = "4.5.",
                            Instances = new List<ThreatInstance> {
                                new ThreatInstance {
                                     ExtraDescription = null,
                                      DependsOnFeatures = new List<Test>{
                                          Tests["OAuch.Compliance.Tests.Features.CodeFlowSupportedTest"],
                                      },
                                      MitigatedBy = new List<TestCombination> {
                                          new TestCombination {
                                            Tests["OAuch.Compliance.Tests.Pkce.IsPkceImplementedTest"],
                                            Tests["OAuch.Compliance.Tests.Pkce.HashedPkceDisabledTest"],
                                            Tests["OAuch.Compliance.Tests.Pkce.IsPkceRequiredTest"],
                                          }
                                      }
                                }
                            }
                        },
                        new Threat {
                            Id = "BCP_4_8",
                            Title = "PKCE Downgrade Attack",
                            Description = "An authorization server that supports PKCE but does not make its use mandatory for all flows can be susceptible to a PKCE downgrade attack.",
                            Document = Documents["SecBCP"],
                            LocationInDocument = "4.8.",
                            Instances = new List<ThreatInstance> {
                                new ThreatInstance {
                                     ExtraDescription = null,
                                      DependsOnFeatures = new List<Test>{
                                            Tests["OAuch.Compliance.Tests.Pkce.IsPkceImplementedTest"],
                                      },
                                      MitigatedBy = new List<TestCombination> {
                                          new TestCombination {
                                              Tests["OAuch.Compliance.Tests.Pkce.IsPkceDowngradeDetectedTest"],
                                              Tests["OAuch.Compliance.Tests.Pkce.IsPkcePlainDowngradeDetectedTest"]
                                          }
                                      }
                                }
                            }
                        },
                        new Threat {
                            Id = "7519_6",
                            Title = "Unverified JWTs (resource server)",
                            Description = "An attacker can remove or forge the signature of a JWT to impersonate another user.",
                            Document = Documents["AttsDefs"],
                            LocationInDocument = "",
                            Instances = new List<ThreatInstance> {
                                new ThreatInstance {
                                     ExtraDescription = null,
                                      DependsOnFeatures = new List<Test>{
                                            Tests["OAuch.Compliance.Tests.Features.HasJwtAccessTokensTest"],
                                      },
                                      MitigatedBy = new List<TestCombination> {
                                          new TestCombination {
                                              Tests["OAuch.Compliance.Tests.Jwt.AcceptsNoneSignatureTest"], // API authorization with JWT
                                          }
                                      }
                                }
                            }
                        },
                        new Threat {
                            Id = "7523",
                            Title = "Unverified JWTs for client authentication",
                            Description = "An attacker can use an expired or otherwise invalid token to impersonate another user.",
                            Document = Documents["RFC7523"],
                            LocationInDocument = "4.1.",
                            Instances = new List<ThreatInstance> {
                                new ThreatInstance {
                                     ExtraDescription = null,
                                      DependsOnFeatures = new List<Test>{
                                            Tests["OAuch.Compliance.Tests.Jwt.SupportsJwtClientAuthenticationTest"],
                                      },
                                      MitigatedBy = new List<TestCombination> {
                                          new TestCombination {
                                              Tests["OAuch.Compliance.Tests.Jwt.IsSignatureCheckedTest"], // client authentication with JWT
                                              Tests["OAuch.Compliance.Tests.Jwt.IsSignatureRequiredTest"], // client authentication with JWT
                                              Tests["OAuch.Compliance.Tests.Jwt.HasAudienceClaimTest"],
                                              Tests["OAuch.Compliance.Tests.Jwt.HasIssuerClaimTest"],
                                              Tests["OAuch.Compliance.Tests.Jwt.HasSubjectClaimTest"],
                                              Tests["OAuch.Compliance.Tests.Jwt.IsExpirationCheckedTest"],
                                              Tests["OAuch.Compliance.Tests.Jwt.IsIssuedAtCheckedTest"],
                                              Tests["OAuch.Compliance.Tests.Jwt.IsJwtReplayDetectedTest"],
                                              Tests["OAuch.Compliance.Tests.Jwt.IsNotBeforeCheckedTest"],
                                          }
                                      }
                                }
                            }
                        },
                        new Threat {
                            Id = "7009_1",
                            Title = "Abuse of revoked tokens",
                            Description = "Leaked (and potentially long-lived) access or refesh tokens that cannot be revoked may enable an attacker to impersonate a user.",
                            Document = Documents["RFC7009"],
                            LocationInDocument = "2.1.",
                            Instances = new List<ThreatInstance> {
                                new ThreatInstance {
                                     ExtraDescription = null,
                                      DependsOnFeatures = new List<Test>{
                                            Tests["OAuch.Compliance.Tests.DocumentSupport.RFC7009SupportedTest"],
                                      },
                                      MitigatedBy = new List<TestCombination> {
                                          new TestCombination {
                                              Tests["OAuch.Compliance.Tests.Revocation.AccessRevokesRefreshTest"],
                                              Tests["OAuch.Compliance.Tests.Revocation.CanAccessTokensBeRevokedTest"],
                                              Tests["OAuch.Compliance.Tests.Revocation.CanRefreshTokensBeRevokedTest"],
                                              Tests["OAuch.Compliance.Tests.Revocation.RefreshRevokesAccessTest"],
                                          }
                                      }
                                }
                            }
                        },
                        new Threat {
                            Id = "7009_2",
                            Title = "Unauthorized revocation of tokens",
                            Description = "An authentication server that supports token revocation must verify the ownership of a token before revocation.",
                            Document = Documents["RFC7009"],
                            LocationInDocument = "2.1.",
                            Instances = new List<ThreatInstance> {
                                new ThreatInstance {
                                     ExtraDescription = null,
                                      DependsOnFeatures = new List<Test>{
                                            Tests["OAuch.Compliance.Tests.DocumentSupport.RFC7009SupportedTest"],
                                      },
                                      MitigatedBy = new List<TestCombination> {
                                          new TestCombination {
                                              Tests["OAuch.Compliance.Tests.Revocation.IsBoundToClientTest"],
                                              Tests["OAuch.Compliance.Tests.Revocation.IsClientAuthRequiredTest"],
                                          }
                                      }
                                }
                            }
                        },
                        new Threat {
                            Id = "OIDC_2",
                            Title = "Abuse of incomplete/invalid identity tokens",
                            Description = "An attacker may attempt to re-use an identity token that was acquired for another client or for another authorization session.",
                            Document = Documents["OIDC"],
                            LocationInDocument = "2.",
                            Instances = new List<ThreatInstance> {
                                new ThreatInstance {
                                     ExtraDescription = null,
                                      DependsOnFeatures = new List<Test>{
                                            Tests["OAuch.Compliance.Tests.DocumentSupport.OpenIdSupportedTest"],
                                      },
                                      MitigatedBy = new List<TestCombination> {
                                          new TestCombination {
                                              Tests["OAuch.Compliance.Tests.IdTokens.CodeHashValidTest"],
                                              Tests["OAuch.Compliance.Tests.IdTokens.HasAuthorizedPartyTest"],
                                              Tests["OAuch.Compliance.Tests.IdTokens.HasAzpForMultiAudienceTest"],
                                              Tests["OAuch.Compliance.Tests.IdTokens.HasCorrectAudienceTest"],
                                              Tests["OAuch.Compliance.Tests.IdTokens.HasCorrectIssuerTest"],
                                              Tests["OAuch.Compliance.Tests.IdTokens.HasCorrectMacTest"],
                                              Tests["OAuch.Compliance.Tests.IdTokens.HasRequiredClaimsTest"],
                                              Tests["OAuch.Compliance.Tests.IdTokens.IsAccessTokenHashCorrectTest"],
                                              Tests["OAuch.Compliance.Tests.IdTokens.IsAccessTokenHashPresentTest"],
                                              Tests["OAuch.Compliance.Tests.IdTokens.IsAuthorizationCodeHashPresentTest"],
                                              Tests["OAuch.Compliance.Tests.IdTokens.KeyReferencesTest"],
                                              Tests["OAuch.Compliance.Tests.IdTokens.NoncePresentInTokenTest"],
                                          }
                                      }
                                }
                            }
                        },
                        new Threat {
                            Id = "OIDC_16",
                            Title = "Falsifying identity tokens",
                            Description = "Resource servers that do not verify the signature of an identity token, or that accept identity tokens that are signed with weak keys, are subject to an impersonation attack.",
                            Document = Documents["OIDC"],
                            LocationInDocument = "16.",
                            Instances = new List<ThreatInstance> {
                                new ThreatInstance {
                                     ExtraDescription = null,
                                      DependsOnFeatures = new List<Test>{
                                            Tests["OAuch.Compliance.Tests.DocumentSupport.OpenIdSupportedTest"],
                                      },
                                      MitigatedBy = new List<TestCombination> {
                                          new TestCombination {
                                              Tests["OAuch.Compliance.Tests.IdTokens.ClientSecretLongEnoughTest"],
                                              Tests["OAuch.Compliance.Tests.IdTokens.IsSignedTest"],
                                          }
                                      }
                                }
                            }
                        }
                    };
                }
                return _threats;
            }
        }

        public static Dictionary<string, OAuthDocument> Documents {
            get {
                if (_docDictionary == null) {
                    _docDictionary = new Dictionary<string, OAuthDocument>();
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
                if (_documents == null) {
                    _documents = new List<OAuthDocument> {
                        new OAuthDocument {
                             Id = "RFC6749",
                             Name = "The OAuth 2.0 Authorization Framework",
                             Description = "The OAuth 2.0 authorization framework enables a third-party application to obtain limited access to an HTTP service, either on behalf of a resource owner by orchestrating an approval interaction between the resource owner and the HTTP service, or by allowing the third-party application to obtain access on its own behalf. This document is the base specification of OAuth 2.0.",
                             Url = "https://tools.ietf.org/html/rfc6749",
                             IsSupportedTest = "OAuch.Compliance.Tests.DocumentSupport.RFC6749SupportedTest",
                             IsStandard = true,
                             DocumentCategory = DocumentCategories.OAuth2,
                             DeprecatedFeatures = new List<TestRequirementLevel> {
                                new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Features.IsDeprecatedTlsSupportedTest"],
                                     RequirementLevel = RequirementLevels.May,
                                     LocationInDocument = "1.6. TLS Version"
                                }
                             },
                             Countermeasures= new List<TestRequirementLevel> {
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
                                     Test  = Tests["OAuch.Compliance.Tests.AuthEndpoint.RedirectUriPathMatchedTest"],
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
                             },
                             AdditionalTests = new List<Test> {
                                 Tests["OAuch.Compliance.Tests.Features.HasRefreshTokensTest"],
                                 Tests["OAuch.Compliance.Tests.Features.HasAccessTokensTest"],
                                 Tests["OAuch.Compliance.Tests.Features.CodeFlowSupportedTest"],
                                 Tests["OAuch.Compliance.Tests.Features.HasSupportedFlowsTest"],
                                 Tests["OAuch.Compliance.Tests.Features.ClientCredentialsFlowSupportedTest"],
                                 Tests["OAuch.Compliance.Tests.TokenEndpoint.IsPasswordFlowDisabledTest"],
                                 Tests["OAuch.Compliance.Tests.Features.HasSupportedFlowsTest"],
                                 Tests["OAuch.Compliance.Tests.Features.HasSupportedFlowsTest"],
                                 Tests["OAuch.Compliance.Tests.Features.HasJwtAccessTokensTest"],
                             }
                        },
                        new OAuthDocument {
                            Id = "RFC6750",
                            Name ="The OAuth 2.0 Authorization Framework: Bearer Token Usage",
                            Description = "This specification describes how to use bearer tokens in HTTP requests to access OAuth 2.0 protected resources. Any party in possession of a bearer token can use it to get access to the associated resources (without demonstrating possession of a cryptographic key).",
                            Url = "https://tools.ietf.org/html/rfc6750",
                            IsSupportedTest = "OAuch.Compliance.Tests.DocumentSupport.RFC6750SupportedTest",
                            IsStandard = true,
                            DocumentCategory = DocumentCategories.OAuth2,
                            DeprecatedFeatures = new List<TestRequirementLevel> {
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Features.TokenAsQueryParameterTest"],
                                     RequirementLevel = RequirementLevels.Should,
                                     LocationInDocument = "2.3. URI Query Parameter"
                                 },
                            },
                            Countermeasures = new List<TestRequirementLevel> {
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
                            },
                            AdditionalTests = new List<Test> {
                                 Tests["OAuch.Compliance.Tests.Features.TestUriSupportedTest"],
                                 Tests["OAuch.Compliance.Tests.ApiEndpoint.TokenAsQueryParameterDisabledTest"],
                             }
                        },
                        new OAuthDocument {
                            Id = "RFC8628",
                            Name = "RFC8628 - OAuth 2.0 Device Authorization Grant",
                            Description = "The OAuth 2.0 device authorization grant is designed for Internet-connected devices that either lack a browser to perform a user-agent-based authorization or are input constrained to the extent that requiring the user to input text in order to authenticate during the authorization flow is impractical.",
                            Url = "https://tools.ietf.org/html/rfc8628",
                            IsSupportedTest = "OAuch.Compliance.Tests.DocumentSupport.RFC8628SupportedTest",
                            IsStandard = true,
                            DocumentCategory = DocumentCategories.OAuth2,
                            DeprecatedFeatures = new List<TestRequirementLevel> {
                                new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Features.IsDeprecatedTlsSupportedTest"],
                                     RequirementLevel = RequirementLevels.May,
                                     LocationInDocument = "3.1. Device Authorization Request"
                                }
                            },
                            Countermeasures = new List<TestRequirementLevel> {
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
                            },
                            AdditionalTests = new List<Test> {
                                 Tests["OAuch.Compliance.Tests.Features.DeviceFlowSupportedTest"],
                             }
                        },
                        new OAuthDocument {
                            Id = "RFC7636",
                            Name = "Proof Key for Code Exchange by OAuth Public Clients",
                            Description = "OAuth 2.0 public clients utilizing the Authorization Code Grant are susceptible to the authorization code interception attack.  This specification describes the attack as well as a technique to mitigate against the threat through the use of Proof Key for Code Exchange (PKCE, pronounced 'pixy').",
                            Url = "https://tools.ietf.org/html/rfc7636",
                            IsSupportedTest = "OAuch.Compliance.Tests.DocumentSupport.RFC7636SupportedTest",
                            IsStandard = true,
                            DocumentCategory = DocumentCategories.OAuth2,
                            DeprecatedFeatures = new List<TestRequirementLevel> {
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.Features.PlainPkceTest"],
                                     RequirementLevel = RequirementLevels.Should,
                                     LocationInDocument = "4.2. Client Creates the Code Challenge"
                                 },
                            },
                            Countermeasures = new List<TestRequirementLevel> {
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

                            }
                        },
                        new OAuthDocument {
                            Id = "RFC6819",
                            Name = "OAuth 2.0 Threat Model and Security Considerations",
                            Description = "This document gives additional security considerations for OAuth, beyond those in the OAuth 2.0 specification, based on a comprehensive threat model for the OAuth 2.0 protocol.",
                            Url = "https://tools.ietf.org/html/rfc6819",
                            IsSupportedTest = "OAuch.Compliance.Tests.DocumentSupport.RFC6819SupportedTest",
                            IsStandard = true,
                            DocumentCategory = DocumentCategories.OAuth2,
                            DeprecatedFeatures = new List<TestRequirementLevel> { 
                                //
                            },
                            Countermeasures = new List<TestRequirementLevel> {
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
                                     Test  = Tests["OAuch.Compliance.Tests.AuthEndpoint.RedirectUriPathMatchedTest"],
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
                            },
                        },
                        new OAuthDocument {
                            Id = "RFC7523",
                            Name = "JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and Authorization Grants",
                            Description = "This specification defines the use of a JSON Web Token (JWT) Bearer Token as a means for requesting an OAuth 2.0 access token as well as for client authentication.",
                            Url = "https://tools.ietf.org/html/rfc7523",
                            IsSupportedTest = "OAuch.Compliance.Tests.DocumentSupport.RFC7523SupportedTest",
                            IsStandard = true,
                            DocumentCategory = DocumentCategories.OAuth2,
                            DeprecatedFeatures = new  List<TestRequirementLevel> {
                                //
                            },
                            Countermeasures = new  List<TestRequirementLevel> {
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
                            },
                        },
                        new OAuthDocument {
                            Id = "RFC7009",
                            Name = "OAuth 2.0 Token Revocation",
                            Description = "This document proposes an additional endpoint for OAuth authorization servers, which allows clients to notify the authorization server that a previously obtained refresh or access token is no longer needed. This allows the authorization server to clean up security credentials.",
                            Url = "https://tools.ietf.org/html/rfc7009",
                            IsSupportedTest = "OAuch.Compliance.Tests.DocumentSupport.RFC7009SupportedTest",
                            IsStandard = true,
                            DocumentCategory = DocumentCategories.OAuth2,
                            DeprecatedFeatures  = new List<TestRequirementLevel> {
                                //
                             },
                            Countermeasures= new List<TestRequirementLevel> {
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

                            }
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
                            Name = "OAuth 2.0 Security Best Current Practice (draft 23)",
                            Description = "This document describes best current security practice for OAuth 2.0. It updates and extends the OAuth 2.0 Security Threat Model to incorporate practical experiences gathered since OAuth 2.0 was published and covers new threats relevant due to the broader application of OAuth 2.0.",
                            Url = "https://tools.ietf.org/html/draft-ietf-oauth-security-topics",
                            IsSupportedTest = "OAuch.Compliance.Tests.DocumentSupport.RFC6749SupportedTest",
                            IsStandard = false,
                            DocumentCategory = DocumentCategories.Draft,
                            DeprecatedFeatures  = new List<TestRequirementLevel> {
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
                             },
                            Countermeasures= new List<TestRequirementLevel> {
                                 new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.AuthEndpoint.RedirectUriFullyMatchedTest"],
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

                            }
                        },
                        new OAuthDocument {
                            Id = "OIDC",
                            Name = "OpenID Connect Core 1.0 incorporating errata set 1",
                            Description = "OpenID Connect 1.0 is a simple identity layer on top of the OAuth 2.0 protocol. It enables Clients to verify the identity of the End-User based on the authentication performed by an Authorization Server, as well as to obtain basic profile information about the End-User in an interoperable and REST-like manner. This specification defines the core OpenID Connect functionality: authentication built on top of OAuth 2.0 and the use of Claims to communicate information about the End-User. It also describes the security and privacy considerations for using OpenID Connect.",
                            Url = "https://openid.net/specs/openid-connect-core-1_0.html",
                            IsSupportedTest = "OAuch.Compliance.Tests.DocumentSupport.OpenIdSupportedTest",
                             IsStandard = true,
                             DocumentCategory = DocumentCategories.OpenIDConnect,
                             DeprecatedFeatures  = new List<TestRequirementLevel> {
                                 //
                             },
                             Countermeasures= new List<TestRequirementLevel> {
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
                             },
                             AdditionalTests = new List<Test> {
                                 Tests["OAuch.Compliance.Tests.Features.CodeIdTokenFlowSupportedTest"],
                                 Tests["OAuch.Compliance.Tests.Features.IdTokenFlowSupportedTest"],
                             }
                        },
                        new OAuthDocument {
                            Id = "FormPost",
                            Name = "OAuth 2.0 Form Post Response Mode",
                            Description = "This specification defines the Form Post Response Mode. In this mode, Authorization Response parameters are encoded as HTML form values that are auto-submitted in the User Agent, and thus are transmitted via the HTTP POST method to the Client, with the result parameters being encoded in the body using the application/x-www-form-urlencoded format.",
                            Url = "https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html",
                            IsSupportedTest = "OAuch.Compliance.Tests.DocumentSupport.FormPostSupportedTest",
                            IsStandard = true,
                            DocumentCategory = DocumentCategories.OAuth2,
                            DeprecatedFeatures  = new List<TestRequirementLevel> {
                                 //
                            },
                            Countermeasures= new List<TestRequirementLevel> {
                                new TestRequirementLevel {
                                     Test  = Tests["OAuch.Compliance.Tests.AuthEndpoint.SupportsPostResponseModeTest"],
                                     RequirementLevel = RequirementLevels.Must,
                                     LocationInDocument = "2. Form Post Response Mode"
                                }
                            }
                        },
                        new OAuthDocument {
                            Id = "FAPI1Base",
                            Name = "Financial-grade API Security Profile (FAPI) 1.0 – Part 1: Baseline",
                            Description = "A secured OAuth profile that aims to provide specific implementation guidelines for security and interoperability.",
                            Url = "https://openid.net/specs/openid-financial-api-part-1-1_0.html",
                            IsSupportedTest = "OAuch.Compliance.Tests.DocumentSupport.OpenIdSupportedTest",
                            IsStandard = true,
                            DocumentCategory = DocumentCategories.OpenIDConnect,
                            DeprecatedFeatures  = new List<TestRequirementLevel> {
                                 new TestRequirementLevel {
                                    Test = Tests["OAuch.Compliance.Tests.Features.IsDeprecatedTlsSupportedTest"],
                                    RequirementLevel = RequirementLevels.Must,
                                    LocationInDocument = "7.1. TLS and DNSSEC considerations"
                                 }
                            },
                            Countermeasures= new List<TestRequirementLevel> {
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
                            }
                        },
                        new OAuthDocument {
                            Id = "FAPI1Adv",
                            Name = "Financial-grade API Security Profile (FAPI) 1.0 – Part 2: Advanced",
                            Description = "A highly secured OAuth profile that aims to provide specific implementation guidelines for security and interoperability.",
                            Url = "https://openid.net/specs/openid-financial-api-part-2-1_0.html",
                            IsSupportedTest = "OAuch.Compliance.Tests.DocumentSupport.OpenIdSupportedTest",
                            IsStandard = true,
                            DocumentCategory = DocumentCategories.OpenIDConnect,
                            DeprecatedFeatures  = new List<TestRequirementLevel> {
                                 new TestRequirementLevel { 
                                    Test = Tests["OAuch.Compliance.Tests.Features.IsDeprecatedTlsSupportedTest"],
                                    RequirementLevel = RequirementLevels.Must,
                                    LocationInDocument = "8.5. TLS considerations"
                                 }
                            },
                            Countermeasures= new List<TestRequirementLevel> {
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


                            }
                        },
                        new OAuthDocument {
                            Id = "AttsDefs",
                            Name = "OAuth 2.0 Attacks & Defenses",
                            Description = "This document contains a small set of test cases for attacks on OAuth implementations that are not covered by the other documents.",
                            Url = "",
                            IsSupportedTest = "OAuch.Compliance.Tests.DocumentSupport.RFC6749SupportedTest",
                            IsStandard = false,
                            DocumentCategory = DocumentCategories.Other,
                            DeprecatedFeatures  = new List<TestRequirementLevel> {
                                 //
                             },
                             Countermeasures= new List<TestRequirementLevel> {
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
                             }
                        }
                    };
                }
                return _documents;
            }
        }
    }
}
