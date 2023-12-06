using Assesment.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.IdentityModel.Tokens.Jwt;

namespace Assesment.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly UserContext userContext;
        private readonly IPasswordHasher<User> passwordHasher;
        private readonly string jwtSecretKey = "n8EqT8q5u9#Ty4Fw@6#kL2S!w3JpHr%G";

        public AuthController(UserContext _userContext, IPasswordHasher<User> _passwordHasher)
        {
            this.userContext = _userContext;
            this.passwordHasher = _passwordHasher;
        }

        
        [HttpPost("Register")]
        public async Task<IActionResult> Register([FromBody] User userRegistration)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest("Invalid model state");
            }

            try
            {
                var existingUser = await userContext.Users.FirstOrDefaultAsync(u => u.Email == userRegistration.Email);

                if (existingUser != null)
                {
                    return Conflict("Email already exists");
                }

                string hashedPassword = passwordHasher.HashPassword(null, userRegistration.Password);

               
                User newUser = new User
                {
                    FirstName = userRegistration.FirstName,
                    LastName = userRegistration.LastName,
                    Email = userRegistration.Email,
                    Password = hashedPassword
                };

                
                userContext.Users.Add(newUser);
                await userContext.SaveChangesAsync();

                return Ok("User registered successfully");
            }
            catch (Exception ex)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, $"Error: {ex.Message}");
            }
        }
        [HttpPost("Login")]
        public async Task<IActionResult> Login([FromBody] User userLogin)
        {
            try
            {
                
                var user = await userContext.Users.FirstOrDefaultAsync(u => u.Email == userLogin.Email);

                if (user == null || !passwordHasher.VerifyHashedPassword(null, user.Password, userLogin.Password).Equals(PasswordVerificationResult.Success))
                {
                    return Unauthorized("Invalid email or password");
                }

                
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.ASCII.GetBytes(jwtSecretKey);
                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(new Claim[]
                    {
                    new Claim(ClaimTypes.NameIdentifier, user.ID.ToString()),
                    new Claim(ClaimTypes.Email, user.Email)
                        
                    }),
                    Expires = DateTime.UtcNow.AddHours(1), 
                    SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
                };
                var token = tokenHandler.CreateToken(tokenDescriptor);
                var tokenString = tokenHandler.WriteToken(token);

                return Ok(new { Token = tokenString });
            }
            catch (Exception ex)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, $"Error: {ex.Message}");
            }
        }
    }
}
