using System;
using System.Collections.Generic;
using System.Drawing;
using PowerShellTerminal.Domain.Entities;
using PowerShellTerminal.Domain.Models;

namespace PowerShellTerminal.Application.Services
{
    using PowerShellTerminal.Application.Patterns.Factory;

    public class ThemeManager
    {
        private TerminalTheme _currentTheme;
        private IThemeFactory _factory;

        public ThemeManager()
        {
            _currentTheme = new TerminalTheme();
        }

        public ThemeManager(IThemeFactory factory)
        {
            _factory = factory;
            _currentTheme = factory?.CreateTheme() ?? new TerminalTheme();
        }

        public void SetFactory(IThemeFactory factory)
        {
            _factory = factory;
            if (_factory != null)
                _currentTheme = _factory.CreateTheme();
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

        public void ApplyTheme(TerminalTheme theme)
        {
            if (theme != null)
            {
                _currentTheme = theme.Clone();
            }
        }

        public TerminalControl CreateTerminalControl(CommandInterpreter interpreter, HistoryService historyService)
        {
            if (_factory != null)
                return _factory.CreateTerminalControl(interpreter, historyService);

            return new TerminalControl(interpreter, historyService);
        }

        public void ApplyLightTheme()
        {
            var light = new TerminalTheme
            {
                BackgroundColor = Color.White,
                ForegroundColor = Color.Black,
                ErrorColor = Color.Red,
                DefaultFont = new Font("Consolas", 12)
            };
            ApplyTheme(light);
        }

        public void ApplyDarkTheme()
        {
            var dark = new TerminalTheme
            {
                BackgroundColor = Color.FromArgb(20, 20, 20),
                ForegroundColor = Color.FromArgb(230, 230, 230),
                ErrorColor = Color.OrangeRed,
                DefaultFont = new Font("Consolas", 12)
            };
            ApplyTheme(dark);
        }

        public void ChangeFontSize(int size)
        {
            if (_currentTheme.DefaultFont != null)
            {
                _currentTheme.DefaultFont = new Font(_currentTheme.DefaultFont.FontFamily, size);
            }
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