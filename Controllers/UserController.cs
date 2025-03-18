using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using FinanceTracker.Server.Models;
using FinanceTracker.Server.Services;
using Microsoft.AspNetCore.Http;

namespace FinanceTracker.Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize]
    public class UserController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly FileStorageService _fileStorageService;
        private readonly UserService _userService;

        public UserController(UserManager<ApplicationUser> userManager,
                              FileStorageService fileStorageService,
                              UserService userService)
        {
            _userManager = userManager;
            _fileStorageService = fileStorageService;
            _userService = userService;
        }

        [HttpGet]
        public async Task<IActionResult> GetProfile()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(userId))
                return Unauthorized();

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return NotFound("User not found.");

            return Ok(new
            {
                user.Id,
                user.Email,
                user.FirstName,
                user.LastName,
                user.DateOfBirth,
                user.Address,
                user.Gender,
                user.ProfilePictureUrl
            });
        }

        public class UpdateUserDto
        {
            public string FirstName { get; set; } = string.Empty;
            public string LastName { get; set; } = string.Empty;
            public DateTime? DateOfBirth { get; set; }
            public string Address { get; set; } = string.Empty;
            public string Gender { get; set; } = string.Empty;
        }

        [HttpPut]
        public async Task<IActionResult> UpdateProfile([FromBody] UpdateUserDto dto)
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(userId))
                return Unauthorized();

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return NotFound("User not found.");

            user.FirstName = dto.FirstName;
            user.LastName = dto.LastName;
            user.DateOfBirth = dto.DateOfBirth;
            user.Address = dto.Address;
            user.Gender = dto.Gender;

            var result = await _userManager.UpdateAsync(user);
            if (!result.Succeeded)
            {
                return BadRequest(result.Errors.FirstOrDefault()?.Description);
            }
            return Ok("Profile updated successfully.");
        }

        [HttpPost("uploadProfilePicture")]
        public async Task<IActionResult> UploadProfilePicture(IFormFile file)
        {
            if (file == null || file.Length == 0)
                return BadRequest("No file uploaded.");

            try
            {
                // Save the file and get the relative path (e.g., "/uploads/unique-file.jpg")
                var filePath = await _fileStorageService.SaveFileAsync(file);

                // Build an absolute URL using the current request scheme and host
                var absoluteUrl = $"{Request.Scheme}://{Request.Host}{filePath}";

                var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
                if (string.IsNullOrEmpty(userId))
                    return Unauthorized();

                var user = await _userManager.FindByIdAsync(userId);
                if (user == null)
                    return NotFound("User not found.");

                user.ProfilePictureUrl = absoluteUrl;
                var updateResult = await _userManager.UpdateAsync(user);
                if (!updateResult.Succeeded)
                    return BadRequest("Failed to update profile picture.");

                return Ok(new { profilePictureUrl = absoluteUrl });
            }
            catch (Exception ex)
            {
                return StatusCode(500, "An error occurred while uploading the file: " + ex.Message);
            }
        }

        [HttpGet("test-error")]
        public IActionResult TestError()
        {
            throw new Exception("This is a test exception.");
        }
    }
}
