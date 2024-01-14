namespace JwtUtilities;

public class JwtSettings
{
    public const string SchemeName = "Bearer";
    public string SigningKeySecret { get; set; }
}
