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
                var databasePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "powershellterminal.db");
                Console.WriteLine($"🔍 Checking database at: {databasePath}");
                Console.WriteLine($"📁 File exists: {File.Exists(databasePath)}");
                
                bool created = _context.Database.EnsureCreated();
                Console.WriteLine($"✅ Database ensured: {created}");
                
                // Перевіримо кількість записів
                var count = _context.CommandHistories.Count();
                Console.WriteLine($"📊 Current commands in database: {count}");
                
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Database creation failed: {ex.Message}");
                Console.WriteLine($"Stack trace: {ex.StackTrace}");
            }
        }

        public async Task AddAsync(CommandHistory entity)
        {
            try
            {
                Console.WriteLine($"💾 Starting to save command: {entity.Command}");
                
                await _context.CommandHistories.AddAsync(entity);
                Console.WriteLine("Entity added to context");
                
                int changes = await _context.SaveChangesAsync();
                Console.WriteLine($"✅ Command saved to database. Changes: {changes}");
                
                // Перевіримо, чи дійсно збереглося
                var countAfter = _context.CommandHistories.Count();
                Console.WriteLine($"📊 Commands in database after save: {countAfter}");
                
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Error adding command to database: {ex.Message}");
                Console.WriteLine($"Inner exception: {ex.InnerException?.Message}");
                Console.WriteLine($"Stack trace: {ex.StackTrace}");
                throw;
            }
        }

        // ... інші методи залишаються без змін ...

        public async Task<List<CommandHistory>> GetRecentCommandsAsync(int count = 50)
        {
            try
            {
                var commands = await _context.CommandHistories
                    .OrderByDescending(ch => ch.ExecutedAt)
                    .Take(count)
                    .ToListAsync();
                    
                
                Console.WriteLine($"📋 Retrieved {commands.Count} commands from database");
                return commands;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Error retrieving commands: {ex.Message}");
                return new List<CommandHistory>();
                
            }
        }

        public void Dispose()
        {
            _context?.Dispose();
        }
    }
}