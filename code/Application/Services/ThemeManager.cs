using System;
using System.Collections.Generic;
using System.Drawing;
using PowerShellTerminal.Domain.Entities;
using PowerShellTerminal.Domain.Models;
using PowerShellTerminal.Domain.Observer;

namespace PowerShellTerminal.Application.Services
{
    public class ThemeManager : ISubject
    {
        private TerminalTheme _currentTheme;
        private readonly List<IObserver> _observers = new List<IObserver>();

        public ThemeManager()
        {
            _currentTheme = new TerminalTheme();
        }

        public void Attach(IObserver observer)
        {
            if (observer != null) _observers.Add(observer);
        }

        public void Detach(IObserver observer)
        {
            _observers.Remove(observer);
        }

        // Notify all observers of a theme change.
        public void Notify()
        {
            foreach (var observer in _observers)
            {
                observer.Notify();
            }
        }

        // Apply theme from user settings or create a default theme.
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
            if (_currentTheme.DefaultFont != null)
            {
                _currentTheme.DefaultFont = new Font(_currentTheme.DefaultFont.FontFamily, size);
                Notify();
            }
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