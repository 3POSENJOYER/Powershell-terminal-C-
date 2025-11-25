using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using PowerShellTerminal.Domain.Entities;
using PowerShellTerminal.Infrastructure.Data;

namespace PowerShellTerminal.Infrastructure.Repositories
{
    public class TerminalSessionRepository : IDisposable
    {
        private readonly TerminalDbContext _context;

        public TerminalSessionRepository()
        {
            _context = new TerminalDbContext();
            _context.Database.EnsureCreated();
        }

        public async Task<TerminalSession> GetByIdAsync(int id) => await _context.TerminalSessions.FindAsync(id);

        public async Task<List<TerminalSession>> GetAllAsync() => await _context.TerminalSessions.ToListAsync();

        public async Task<List<TerminalSession>> FindAsync(Func<TerminalSession, bool> predicate)
        {
            return await Task.Run(() => _context.TerminalSessions.Where(predicate).ToList());
        }

        // Add a new session.
        public async Task AddAsync(TerminalSession entity)
        {
            await _context.TerminalSessions.AddAsync(entity);
            await _context.SaveChangesAsync();
        }

        // Update an existing session.
        public async Task UpdateAsync(TerminalSession entity)
        {
            _context.TerminalSessions.Update(entity);
            await _context.SaveChangesAsync();
        }

        public async Task DeleteAsync(TerminalSession entity)
        {
            _context.TerminalSessions.Remove(entity);
            await _context.SaveChangesAsync();
        }

        // Get all active sessions.
        public async Task<List<TerminalSession>> GetActiveSessionsAsync()
        {
            return await _context.TerminalSessions.Where(s => s.IsActive).ToListAsync();
        }

        public void Dispose()
        {
            _context?.Dispose();
        }
    }
}