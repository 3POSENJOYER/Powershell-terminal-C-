using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using PowerShellTerminal.Domain.Entities;
using PowerShellTerminal.Infrastructure.Data;

namespace PowerShellTerminal.Infrastructure.Repositories
{
    public class CommandHistoryRepository : IDisposable
    {
        private readonly TerminalDbContext _context;

        public CommandHistoryRepository()
        {
            _context = new TerminalDbContext();
            _context.Database.EnsureCreated();
        }

        // Add a new command history entry and save.
        public async Task AddAsync(CommandHistory entity)
        {
            try
            {
                await _context.CommandHistories.AddAsync(entity);
                await _context.SaveChangesAsync();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Save error: {ex.Message}");
                throw;
            }
        }

        // Get the N most recent commands, ordered by execution time.
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
