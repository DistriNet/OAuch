using OAuch.Database.Entities;
using System;
using System.Collections.Generic;

namespace OAuch.ViewModels {
    public interface IMenuInformation {
        IList<Site>? Sites { get; set; }
        Site? ActiveSite { get; set; }
        PageType PageType { get; set; }
    }
    [Flags]
    public enum PageType : int {
        Unknown = 0b0,
        Overview = 0b1,
        Settings = 0b100000,
        Results = 0b10,
        Certificates = 0b11,
        AddSite = 0b100,
        Import = 0b101,
        Export = 0b110,
        Other = 0b1000000000000000000000000000000
    }
}
