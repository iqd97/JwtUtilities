using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace JwtUtilities;

public class JwtAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    private readonly JwtService _jwtService;

    public JwtAuthenticationHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        ISystemClock clock,
        JwtService jwtService
    )
        : base(options, logger, encoder, clock)
    {
        _jwtService = jwtService;
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var authorization = Request.Headers.Authorization.ToString();

        if (string.IsNullOrWhiteSpace(authorization))
            return Task.FromResult(Failure());

        return _jwtService.ValidateJwt(authorization, out var jwtPrincipal)
            ? Task.FromResult(Success(jwtPrincipal))
            : Task.FromResult(Failure());

        AuthenticateResult Success(ClaimsPrincipal principal) =>
            AuthenticateResult.Success(new AuthenticationTicket(principal, JwtSettings.SchemeName));

        AuthenticateResult Failure() => AuthenticateResult.Fail("Failed to validate JWT");
    }
}
