using PowerShellTerminal.Domain.Entities;
using PowerShellTerminal.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;

namespace PowerShellTerminal.Infrastructure.Repositories
{
    public class CommandHistoryRepository : IDisposable
    {
        private readonly TerminalDbContext _context;

        public CommandHistoryRepository()
        {
            _context = new TerminalDbContext();
            EnsureDatabaseCreated();
        }

        private void EnsureDatabaseCreated()
        {
            try
            {
                bool created = _context.Database.EnsureCreated();
                Console.WriteLine($"Database ensured: {created}");

                var count = _context.CommandHistories.Count();
                Console.WriteLine($"Commands in database: {count}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"DB creation error: {ex.Message}");
            }
        }

        public async Task AddAsync(CommandHistory entity)
        {
            try
            {
                await _context.CommandHistories.AddAsync(entity);
                await _context.SaveChangesAsync();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error saving: {ex.Message}");
                throw;
            }
        }

        public async Task<List<CommandHistory>> GetRecentCommandsAsync(int count = 50)
        {
            return await _context.CommandHistories
                .OrderByDescending(x => x.ExecutedAt)
                .Take(count)
                .ToListAsync();
        }

        public void Dispose()
        {
            _context?.Dispose();
        }
    }
}
