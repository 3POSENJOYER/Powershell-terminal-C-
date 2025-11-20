using PowerShellTerminal.Domain.Entities;
using PowerShellTerminal.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
using System.Windows.Forms;

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

        public async Task<TerminalSession> GetByIdAsync(int id)
        {
            return await _context.TerminalSessions.FindAsync(id);
        }

        public async Task<List<TerminalSession>> GetAllAsync()
        {
            return await _context.TerminalSessions.ToListAsync();
        }

        public async Task<List<TerminalSession>> FindAsync(Func<TerminalSession, bool> predicate)
        {
            return await Task.Run(() => _context.TerminalSessions.Where(predicate).ToList());
        }

        public async Task AddAsync(TerminalSession entity)
        {
            await _context.TerminalSessions.AddAsync(entity);
            await _context.SaveChangesAsync();
        }

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

        public async Task SaveAsync()
        {
            await _context.SaveChangesAsync();
        }

        public async Task<TerminalSession> StartNewSessionAsync()
        {
            var session = new TerminalSession
            {
                SessionName = $"Session_{DateTime.Now:yyyyMMdd_HHmmss}",
                StartedAt = DateTime.Now,
                InitialDirectory = Directory.GetCurrentDirectory(),
                IsActive = true
            };

            await _context.TerminalSessions.AddAsync(session);
            await _context.SaveChangesAsync();
            return session;
        }

        public async Task EndSessionAsync(int sessionId)
        {
            var session = await _context.TerminalSessions.FindAsync(sessionId);
            if (session != null)
            {
                session.EndedAt = DateTime.Now;
                session.IsActive = false;
                await _context.SaveChangesAsync();
            }
        }

        public async Task<List<TerminalSession>> GetActiveSessionsAsync()
        {
            return await _context.TerminalSessions
                .Where(ts => ts.IsActive)
                .ToListAsync();
        }

        public void Dispose()
        {
            _context?.Dispose();
        }
    }
}