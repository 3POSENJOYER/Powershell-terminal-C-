using PowerShellTerminal.Domain.Entities;
using PowerShellTerminal.Domain.Models;
using System.Drawing;

namespace PowerShellTerminal.Application.Services
{
    public class ThemeManager
    {
        private TerminalTheme _currentTheme;

        public ThemeManager()
        {
            _currentTheme = new TerminalTheme
            {
                BackgroundColor = Color.Black,
                ForegroundColor = Color.Lime,
                ErrorColor = Color.Red,
                DefaultFont = new Font("Consolas", 10)
            };
        }

        public void ApplyTheme(UserSettings settings = null)
        {
            if (settings != null)
            {
                _currentTheme = new TerminalTheme
                {
                    BackgroundColor = Color.FromName(settings.BackgroundColor),
                    ForegroundColor = Color.FromName(settings.ForegroundColor),
                    ErrorColor = Color.Red,
                    DefaultFont = new Font(settings.FontFamily, settings.FontSize)
                };
            }
        }

        public void ChangeFontSize(int size)
        {
            _currentTheme.DefaultFont = new Font(_currentTheme.DefaultFont.FontFamily, size);
        }

        public void ChangeBackgroundColor(Color color)
        {
            _currentTheme.BackgroundColor = color;
        }

        public void ChangeTextColor(Color color)
        {
            _currentTheme.ForegroundColor = color;
        }

        public TerminalTheme GetCurrentTheme() => _currentTheme;
    }
}