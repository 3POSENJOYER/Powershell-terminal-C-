using PowerShellTerminal.Domain.Entities;
using PowerShellTerminal.Domain.Models;
using PowerShellTerminal.Domain.Observer;
using System.Drawing;

namespace PowerShellTerminal.Application.Services
{
    public class ThemeManager : ISubject
    {
        private TerminalTheme _currentTheme;
        private List<IObserver> _observers = new();

        public ThemeManager()
        {
            _currentTheme = new TerminalTheme();
        }

        public void Attach(IObserver observer)
        {
            _observers.Add(observer);
        }

        public void Detach(IObserver observer)
        {
            _observers.Remove(observer);
        }

        public void Notify()
        {
            foreach (var observer in _observers)
            {
                observer.Notify();
            }
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
            
            Notify();
        }

        public void ChangeFontSize(int size)
        {
            _currentTheme.DefaultFont = new Font(_currentTheme.DefaultFont.FontFamily, size);
            Notify();
        }

        public void ChangeBackgroundColor(Color color)
        {
            _currentTheme.BackgroundColor = color;
            Notify();
        }

        public void ChangeTextColor(Color color)
        {
            _currentTheme.ForegroundColor = color;
            Notify();
        }

        public TerminalTheme GetCurrentTheme() => _currentTheme;
    }
}