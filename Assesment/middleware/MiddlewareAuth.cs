using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Assesment.middleware
{
    public class MiddlewareAuth
    {
        private readonly RequestDelegate _next;
        private readonly string _jwtSecretKey = "n8EqT8q5u9#Ty4Fw@6#kL2S!w3JpHr%G"; //  JWT secret key

        public MiddlewareAuth(RequestDelegate next)
        {
            _next = next;
        }

        // MiddlewareAuth Invoke method handles JWT token validation and extraction
        public async Task Invoke(HttpContext context)
        {
            // Extract JWT token from Authorization header
            var token = context.Request.Headers["Authorization"].FirstOrDefault()?.Split(" ").Last();

            if (token != null)
            {
                // Attaches user claims to the current context if the token is valid
                AttachUserToContext(context, token);
            }

            await _next(context);
        }

       
        private void AttachUserToContext(HttpContext context, string token)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_jwtSecretKey);

            // Validates the provided token using the secret key and specified parameters
            tokenHandler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = false,
                ValidateAudience = false,
                ClockSkew = TimeSpan.Zero
            }, out SecurityToken validatedToken);

            var jwtToken = (JwtSecurityToken)validatedToken;
            var claims = jwtToken.Claims;

            // Store the extracted claims in the current context's Items collection for later use
            context.Items["User"] = new ClaimsPrincipal(new ClaimsIdentity(claims));
        }
    }

    public static class JwtMiddlewareExtensions
    {
        // Extension method to use the JWT middleware in the application
        public static IApplicationBuilder UseJwtMiddleware(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<MiddlewareAuth>();
        }
    }
}
