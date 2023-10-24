﻿using System.ComponentModel.DataAnnotations;

namespace SignUpApi.Models;

public class UserLoginRequest
{
	[Required, EmailAddress]
	public string Email { get; set; } = string.Empty;

	[Required(ErrorMessage = "Try Again!")]
	public string Password { get; set; } = string.Empty;
}
