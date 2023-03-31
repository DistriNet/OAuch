using Microsoft.AspNetCore.Mvc;
using OAuch.ViewModels;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OAuch.Controllers {
    public abstract class BaseController : Controller {
        public Guid? OAuchInternalId {
            get {
                // This version of OAuch doesn't support multiple users
                // so we always return the same user ID 
                return Guid.Empty;
            }
        }
    }
}