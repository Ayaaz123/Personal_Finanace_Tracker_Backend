using System;
using Microsoft.AspNetCore.Identity;

namespace FinanceTracker.Server.Models
{
    public class ApplicationUser : IdentityUser
    {

        public string FirstName { get; set; } = string.Empty;
        public string LastName { get; set; } = string.Empty;
        public DateTime? DateOfBirth { get; set; }
        public string Address { get; set; } = string.Empty;
        public string Gender { get; set; } = string.Empty;


        public string ProfilePictureUrl { get; set; } = string.Empty;
    }
}
