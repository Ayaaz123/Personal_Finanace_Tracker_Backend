using Microsoft.AspNetCore.Identity;
using FinanceTracker.Server.Models;

namespace FinanceTracker.Server.Services
{
    public class UserService
    {
        private readonly UserManager<ApplicationUser> _userManager;

        public UserService(UserManager<ApplicationUser> userManager)
        {
            _userManager = userManager;
        }


        public async Task<ApplicationUser> GetUserProfileAsync(string userId)
        {
            return await _userManager.FindByIdAsync(userId);
        }


        public async Task<bool> UpdateUserProfileAsync(ApplicationUser user)
        {
            var result = await _userManager.UpdateAsync(user);
            return result.Succeeded;
        }
    }
}
