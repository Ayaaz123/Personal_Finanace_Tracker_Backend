using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using FinanceTracker.Server.Data;
using FinanceTracker.Server.Models;
using System.Security.Claims;

namespace FinanceTracker.Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize]
    public class ExpensesController : ControllerBase
    {
        private readonly FinanceContext _context;

        public ExpensesController(FinanceContext context)
        {
            _context = context;
        }


        [HttpGet]
        public IActionResult GetExpenses()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(userId))
                return Unauthorized();

            var expenses = _context.Expenses.Where(e => e.UserId == userId).ToList();
            return Ok(expenses);
        }


        [HttpGet("{id}")]
        public IActionResult GetExpense(int id)
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(userId))
                return Unauthorized();

            var expense = _context.Expenses.FirstOrDefault(e => e.Id == id && e.UserId == userId);
            if (expense == null)
                return NotFound();

            return Ok(expense);
        }


        [HttpPost]
        public IActionResult CreateExpense(Expense expense)
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(userId))
                return Unauthorized();


            expense.UserId = userId;

            if (expense.Amount <= 0)
                return BadRequest("Expense amount must be greater than zero.");

            _context.Expenses.Add(expense);
            _context.SaveChanges();

            return Ok(expense);
        }


        [HttpPut("{id}")]
        public IActionResult UpdateExpense(int id, Expense updatedExpense)
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(userId))
                return Unauthorized();

            var expense = _context.Expenses.FirstOrDefault(e => e.Id == id && e.UserId == userId);
            if (expense == null)
                return NotFound();

            expense.Description = updatedExpense.Description;
            expense.Amount = updatedExpense.Amount;
            expense.Date = updatedExpense.Date;
            expense.Category = updatedExpense.Category;

            _context.SaveChanges();
            return Ok(expense);
        }


        [HttpDelete("{id}")]
        public IActionResult DeleteExpense(int id)
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(userId))
                return Unauthorized();

            var expense = _context.Expenses.FirstOrDefault(e => e.Id == id && e.UserId == userId);
            if (expense == null)
                return NotFound();

            _context.Expenses.Remove(expense);
            _context.SaveChanges();
            return Ok("Expense deleted successfully.");
        }
    }
}
