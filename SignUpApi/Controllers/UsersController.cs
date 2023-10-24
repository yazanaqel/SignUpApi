using Azure.Core;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using System.Security.Cryptography;

namespace SignUpApi.Controllers;
[ApiController]
[Route("[controller]")]
public class UsersController : ControllerBase
{
	private readonly DataContext dataContext;

	public UsersController(DataContext dataContext)
	{
		this.dataContext = dataContext;
	}

	[HttpPost("Register")]
	public async Task<IActionResult> Register(UserRegisterRequest request)
	{
		if (dataContext.Users.Any(x => x.Email == request.Email))
			return BadRequest("Some Thing Went Wrong!");

		CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);

		var user = new User
		{
			Email = request.Email,
			PasswordHash = passwordHash,
			PasswordSalt = passwordSalt,
			VerificationToken = CreateRandomToken(),

		};

		dataContext.Add(user);
		await dataContext.SaveChangesAsync();

		return Ok("User Created!");
	}

	[HttpPost("Login")]
	public async Task<IActionResult> Login(UserLoginRequest request)
	{
		var user = await dataContext.Users.FirstOrDefaultAsync(x => x.Email == request.Email);

		if (user is null)
			return BadRequest("Some Thing Went Wrong!");

		if (!VerifyPasswordHash(request.Password, user.PasswordHash, user.PasswordSalt))
			return BadRequest("Some Thing Went Wrong!");

		if (user.VerificationTime is null)
			return BadRequest("Some Thing Went Wrong!");


		return Ok($"Welcome {user.Email}!");
	}

	[HttpPost("Verify")]
	public async Task<IActionResult> Verify(string token)
	{
		var user = await dataContext.Users.FirstOrDefaultAsync(x => x.VerificationToken == token);

		if (user is null)
			return BadRequest("Some Thing Went Wrong!");

		user.VerificationTime = DateTime.Now;
		await dataContext.SaveChangesAsync();

		return Ok("Verified!");
	}

	[HttpPost("ForgotPassword")]
	public async Task<IActionResult> ForgotPassword(string email)
	{
		var user = await dataContext.Users.FirstOrDefaultAsync(x => x.Email == email);

		if (user is null)
			return BadRequest("Some Thing Went Wrong!");

		user.PasswordResetToken = CreateRandomToken();
		user.ResetTokenExpires = DateTime.Now.AddDays(1);

		await dataContext.SaveChangesAsync();

		return Ok("Reset Password!");
	}

	[HttpPost("ResetPassword")]
	public async Task<IActionResult> ResetPassword(ResetPassworfRequest request)
	{
		var user = await dataContext.Users.FirstOrDefaultAsync(x => x.PasswordResetToken == request.Token);

		if (user is null || user.ResetTokenExpires < DateTime.Now)
			return BadRequest("Some Thing Went Wrong!");

		CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);

		user.PasswordHash = passwordHash;
		user.PasswordSalt = passwordSalt;
		user.PasswordResetToken = null;
		user.ResetTokenExpires = null;

		await dataContext.SaveChangesAsync();

		return Ok("New Password!");
	}

	private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
	{
		using (var hmac = new HMACSHA512())
		{
			passwordSalt = hmac.Key;
			passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
		}
	}
	private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
	{
		using (var hmac = new HMACSHA512(passwordSalt))
		{
			var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));

			return computedHash.SequenceEqual(passwordHash);
		}
	}
	private string CreateRandomToken() => Convert.ToHexString(RandomNumberGenerator.GetBytes(64));
}
