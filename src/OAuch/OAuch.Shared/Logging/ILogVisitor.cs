using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Shared.Logging {
    public interface ILogVisitor {
        void Visit(LoggedString e);
        void Visit(LoggedException e);

        void Visit(LoggedHttpRequest e);
        void Visit(LoggedHttpResponse e);
        void Visit(LoggedJwt e);
        void Visit(LoggedCertificateReport e);
        void Visit(LoggedJwks e);
        void Visit(LoggedTokenResult e);

        void Visit(LoggedTest e);

        void Visit(LoggedCallback e);
        void Visit(LoggedRedirect e);
    }
}
