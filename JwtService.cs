using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
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

    public bool ValidateJwt(string authorizationHeaderValue, out ClaimsPrincipal principal)
    {
        var token = authorizationHeaderValue["Bearer ".Length..].Trim();

        try
        {
            principal = new JwtSecurityTokenHandler().ValidateToken(
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
        }
        catch
        {
            principal = null;
            return false;
        }

        return true;
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
