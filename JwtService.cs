using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.Tokens;

namespace JwtUtilities;

public class JwtService
{
    private readonly JwtSettings _settings;

    public JwtService(JwtSettings settings)
    {
        _settings = settings;
    }

    public string GenerateJwt(IEnumerable<Claim> claims)
    {
        return new JwtSecurityTokenHandler().CreateEncodedJwt(
            new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddYears(1),
                SigningCredentials = GetSigningCredentials()
            }
        );
    }

    public AuthenticateResult ValidateJwt(string authorizationHeaderValue)
    {
        var token = authorizationHeaderValue["Bearer ".Length..].Trim();

        try
        {
            var principal = new JwtSecurityTokenHandler().ValidateToken(
                token,
                new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = GetSigningKey(),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    // set clock skew to zero so tokens expire exactly at token expiration time (instead of 5 minutes later)
                    ClockSkew = TimeSpan.Zero
                },
                out _
            );
            var ticket = new AuthenticationTicket(principal, JwtSettings.SchemeName);

            return AuthenticateResult.Success(ticket);
        }
        catch
        {
            return AuthenticateResult.Fail("Failed to validate JWT");
        }
    }

    private SymmetricSecurityKey GetSigningKey()
    {
        return new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_settings.SigningKeySecret));
    }

    private SigningCredentials GetSigningCredentials()
    {
        return new SigningCredentials(GetSigningKey(), SecurityAlgorithms.HmacSha256Signature);
    }
}
