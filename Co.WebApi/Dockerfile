FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS base
USER $APP_UID
WORKDIR /app
EXPOSE 8080
EXPOSE 8081

FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
ARG BUILD_CONFIGURATION=Release
WORKDIR /src
COPY ["Co.WebApi/Co.WebApi.csproj", "Co.WebApi/"]
COPY ["Co.Application/Co.Application.csproj", "Co.Application/"]
COPY ["Co.Domain/Co.Domain.csproj", "Co.Domain/"]
COPY ["Co.Infrastructure/Co.Infrastructure.csproj", "Co.Infrastructure/"]
RUN dotnet restore "Co.WebApi/Co.WebApi.csproj"
COPY . .
WORKDIR "/src/Co.WebApi"
RUN dotnet build "Co.WebApi.csproj" -c $BUILD_CONFIGURATION -o /app/build

FROM build AS publish
ARG BUILD_CONFIGURATION=Release
RUN dotnet publish "Co.WebApi.csproj" -c $BUILD_CONFIGURATION -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "Co.WebApi.dll"]
