# syntax=docker/dockerfile:1

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS restore
WORKDIR /src

COPY RemoteAdminMCPSharp.csproj ./
RUN dotnet restore RemoteAdminMCPSharp.csproj

FROM restore AS publish
COPY . ./
RUN dotnet publish RemoteAdminMCPSharp.csproj \
    -c Release \
    --no-restore \
    -o /app/publish \
    /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime
WORKDIR /app

ENV ASPNETCORE_ENVIRONMENT=Production \
    REMOTEADMINMCP_Server__Host=0.0.0.0 \
    REMOTEADMINMCP_Server__Port=5079

COPY --from=publish /app/publish ./
RUN mkdir -p logs && chown -R $APP_UID:0 /app

USER $APP_UID
EXPOSE 5079

ENTRYPOINT ["dotnet", "RemoteAdminMCPSharp.dll"]
