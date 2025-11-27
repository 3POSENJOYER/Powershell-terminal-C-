using PowerShellTerminal.Domain.Entities;
using PowerShellTerminal.Domain.Models;
using System.Drawing;
using System.Collections.Generic;


namespace PowerShellTerminal.Application.Services
{
    public class ThemeManager : ISubject
    {
        private TerminalTheme _currentTheme;
        private readonly List<IObserver> _observers;

        public ThemeManager()
        {
            _currentTheme = new TerminalTheme
            {
                DefaultFont = new System.Drawing.Font("Consolas", 10),
                BackgroundColor = System.Drawing.Color.Black,
                ForegroundColor = System.Drawing.Color.Lime,
                ErrorColor = System.Drawing.Color.Red
            };
            _observers = new List<IObserver>();
        }

        public void ApplyTheme(UserSettings settings = null)
        {
            if (settings != null)
            {
                _currentTheme = new TerminalTheme
                {
                    BackgroundColor = ParseColorString(settings.BackgroundColor, Color.Black),
                    ForegroundColor = ParseColorString(settings.ForegroundColor, Color.Lime),
                    ErrorColor = Color.Red,
                    DefaultFont = new Font(settings.FontFamily, settings.FontSize)
                };
            }

            Notify();
        }

        private Color ParseColorString(string colorString, Color defaultColor)
        {
            if (string.IsNullOrWhiteSpace(colorString))
                return defaultColor;

            // Support hex like #RRGGBB
            if (colorString.StartsWith("#"))
            {
                try
                {
                    var r = Convert.ToInt32(colorString.Substring(1, 2), 16);
                    var g = Convert.ToInt32(colorString.Substring(3, 2), 16);
                    var b = Convert.ToInt32(colorString.Substring(5, 2), 16);
                    return Color.FromArgb(r, g, b);
                }
                catch
                {
                    return defaultColor;
                }
            }

            // Try named color
            try
            {
                var named = Color.FromName(colorString);
                if (!named.IsEmpty)
                    return named;
            }
            catch { }

            return defaultColor;
        }

        public void ApplyTheme(TerminalTheme theme)
        {
            if (theme != null)
            {
                _currentTheme = theme.Clone();
                Notify();
            }
        }

        public void ChangeFontSize(int size)
        {
            if (_currentTheme.DefaultFont != null)
            {
                _currentTheme.DefaultFont = new Font(_currentTheme.DefaultFont.FontFamily, size);
            }
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

        public void ApplyLightTheme()
        {
            var light = new TerminalTheme
            {
                BackgroundColor = Color.White,
                ForegroundColor = Color.Black,
                ErrorColor = Color.Red,
                DefaultFont = new Font("Consolas", 10)
            };
            ApplyTheme(light);
        }

        public void ApplyDarkTheme()
        {
            var dark = new TerminalTheme
            {
                BackgroundColor = Color.FromArgb(30, 30, 30),
                ForegroundColor = Color.FromArgb(220, 220, 220),
                ErrorColor = Color.OrangeRed,
                DefaultFont = new Font("Consolas", 10)
            };
            ApplyTheme(dark);
        }
        public void Attach(IObserver obs)
        {
            if (obs != null && !_observers.Contains(obs))
            {
                _observers.Add(obs);
                try
                {
                    obs.Update(_currentTheme.Clone());
                }
                catch
                {
                }
            }
        }

        public void Detach(IObserver obs)
        {
            if (obs != null)
            {
                _observers.Remove(obs);
            }
        }

        public void Notify()
        {
            var themeCopy = _currentTheme.Clone();
            foreach (var obs in _observers)
            {
                obs.Update(themeCopy);
            }
        }
    }
}