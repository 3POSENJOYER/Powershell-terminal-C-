using PowerShellTerminal.Domain.Entities;
using PowerShellTerminal.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
using System.Windows.Forms;

namespace PowerShellTerminal.Infrastructure.Repositories
{
    public class UserSettingsRepository : IDisposable
    {
        private readonly TerminalDbContext _context;

        public UserSettingsRepository()
        {
            _context = new TerminalDbContext();
            _context.Database.EnsureCreated();
        }

        public async Task<UserSettings> GetByIdAsync(int id)
        {
            return await _context.UserSettings.FindAsync(id);
        }

        public async Task<List<UserSettings>> GetAllAsync()
        {
            return await _context.UserSettings.ToListAsync();
        }

        public async Task<List<UserSettings>> FindAsync(Func<UserSettings, bool> predicate)
        {
            return await Task.Run(() => _context.UserSettings.Where(predicate).ToList());
        }

        public async Task AddAsync(UserSettings entity)
        {
            await _context.UserSettings.AddAsync(entity);
            await _context.SaveChangesAsync();
        }

        public async Task UpdateAsync(UserSettings entity)
        {
            _context.UserSettings.Update(entity);
            await _context.SaveChangesAsync();
        }

        public async Task DeleteAsync(UserSettings entity)
        {
            _context.UserSettings.Remove(entity);
            await _context.SaveChangesAsync();
        }

        public async Task SaveAsync()
        {
            await _context.SaveChangesAsync();
        }

        public async Task<UserSettings> GetUserSettingsAsync()
        {
            var settings = await _context.UserSettings.FirstOrDefaultAsync();
            if (settings == null)
            {
                settings = new UserSettings();
                await _context.UserSettings.AddAsync(settings);
                await _context.SaveChangesAsync();
            }
            return settings;
        }

        public async Task SaveUserSettingsAsync(UserSettings settings)
        {
            var existing = await _context.UserSettings.FirstOrDefaultAsync();
            if (existing != null)
            {
                existing.ThemeName = settings.ThemeName;
                existing.FontFamily = settings.FontFamily;
                existing.FontSize = settings.FontSize;
                existing.BackgroundColor = settings.BackgroundColor;
                existing.ForegroundColor = settings.ForegroundColor;
                existing.WindowWidth = settings.WindowWidth;
                existing.WindowHeight = settings.WindowHeight;
                existing.LastModified = DateTime.Now;
                
                _context.UserSettings.Update(existing);
            }
            else
            {
                settings.LastModified = DateTime.Now;
                await _context.UserSettings.AddAsync(settings);
            }
            
            await _context.SaveChangesAsync();
        }

        public void Dispose()
        {
            _context?.Dispose();
        }
    }
}