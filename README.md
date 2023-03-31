# README #

OAuch is an open-source security best practices and threats analyzer for OAuth 2.0 authorization server
implementations. Its main goal is to encourage providers to secure their services by uncovering relevant
threats and pointing out security improvements that could be made in the implementation. OAuth 
implementations are tested using a large set of security-related test cases. The tests are based on the
requirements put forth by the original OAuth 2.0 specification, as well as other documents that refine 
the security assumptions and requirements. These documents include the OAuth threat model, the Security 
Best Current Practices, and others. In addition to OAuth, OAuch also supports OpenID Connect providers.

To build and run the source code in this repository, please follow the following steps:

(1) Clone or download the repository

(2) Open the project in Visual Studio 2022. You can download a free version of Visual Studio 2022 at:
    https://visualstudio.microsoft.com/vs/community/
    Building the project manually (dotnet build/msbuild) or using VS Code will also work, but might
    require more effort.

(3) (optional) Modify the connection string for the database. By default, OAuch stores its data in
    a SQLite database file. The connection string can be modified in the 'appsettings.json' file of
    the 'OAuch' project.
    If you wish to store the data in LocalDB (a database based on MS SQL Server that is installed
    together with Visual Studio), you could use the following connection string:
    "Server=(localdb)\\mssqllocaldb;Database=OAuch;Trusted_Connection=True;MultipleActiveResultSets=true"

(4) (optional) Modify Windows' HOSTS file to override the DNS resolution of oauch.io. Go to the directory
    C:\Windows\System32\drivers\etc and open the 'hosts' file in a text editor. Make sure the text editor
    has administrative privileges (i.e., it has been started via the 'Run as administrator' option). Add
    the following line to the file and save it:  
        `127.0.0.1   oauch.io`  
    Make sure you close all your browser windows after this change. Many browsers use an internal DNS cache
    that is only reset after you close the browser.

(5) Run the project. A web browser window will open and will redirect to https://oauch.io/. If you have
    not made the changes from step (4), you will need to change this address to https://localhost/.
    You are now ready to use OAuch on your local computer!
