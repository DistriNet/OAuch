FROM mcr.microsoft.com/dotnet/sdk:7.0 AS build-env
WORKDIR /OAuch

# Copy everything
COPY . ./
# Restore as distinct layers
RUN dotnet restore
# Build and publish a release
RUN dotnet publish -c Release -o docker-build
RUN dotnet dev-certs https

# Build runtime image
FROM mcr.microsoft.com/dotnet/aspnet:7.0
#FROM mcr.microsoft.com/dotnet/sdk:7.0
WORKDIR /OAuch
COPY --from=build-env /OAuch/docker-build .
COPY --from=build-env /root/.dotnet/corefx/cryptography/x509stores/my/* /root/.dotnet/corefx/cryptography/x509stores/my/
#RUN dotnet dev-certs https
EXPOSE 443
ENTRYPOINT ["dotnet", "OAuch.dll"]
