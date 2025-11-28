using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using PowerShellTerminal.Domain.Entities;
using PowerShellTerminal.Infrastructure.Repositories;

namespace PowerShellTerminal.Application.Services
{
    public class HistoryFacade
    {
        private readonly CommandHistoryRepository _commandHistoryRepository;
        private readonly UserSettingsRepository _userSettingsRepository;
        private readonly TerminalSessionRepository _terminalSessionRepository;

        public HistoryFacade()
        {
            _commandHistoryRepository = new CommandHistoryRepository();
            _userSettingsRepository = new UserSettingsRepository();
            _terminalSessionRepository = new TerminalSessionRepository();
        }

        public async Task SaveCommand(string cmd, string output, string errors)
        {
            var commandHistory = new CommandHistory
            {
                Command = cmd,
                Output = output,
                Errors = errors,
                ExecutedAt = DateTime.Now
            };
            await _commandHistoryRepository.AddAsync(commandHistory);
        }

        public async Task<List<CommandHistory>> GetRecentCommands(int count = 50)
        {
            return await _commandHistoryRepository.GetRecentCommandsAsync(count);
        }

        public async Task<UserSettings> LoadUserSettings()
        {
            var settings = await _userSettingsRepository.GetAllAsync();
            return settings.FirstOrDefault() ?? new UserSettings();
        }

        public async Task SaveUserSettings(UserSettings settings)
        {
            var existing = await _userSettingsRepository.GetAllAsync();
            if (existing.Any())
            {
                settings.Id = existing.First().Id;
                await _userSettingsRepository.UpdateAsync(settings);
            }
            else
            {
                await _userSettingsRepository.AddAsync(settings);
            }
        }

        public async Task StartNewSession()
        {
            var session = new TerminalSession
            {
                StartedAt = DateTime.UtcNow,
                IsActive = true
            };
            await _terminalSessionRepository.AddAsync(session);
        }

        public async Task EndSession()
        {
            var activeSessions = await _terminalSessionRepository.FindAsync(s => s.IsActive);
            foreach (var session in activeSessions)
            {
                session.IsActive = false;
                session.EndedAt = DateTime.UtcNow;
                await _terminalSessionRepository.UpdateAsync(session);
            }
        }
    }
}
