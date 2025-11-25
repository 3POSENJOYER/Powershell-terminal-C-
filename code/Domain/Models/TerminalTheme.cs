using PowerShellTerminal.Domain.Prototype;
using System.Drawing;

namespace PowerShellTerminal.Domain.Models
{
    public class TerminalTheme : IPrototype
    {
        public Color BackgroundColor { get; set; }
        public Color ForegroundColor { get; set; }
        public Color ErrorColor { get; set; }
        public Font DefaultFont { get; set; }

        public TerminalTheme CloneTheme()
        {
            var copy = new TerminalTheme
            {
                BackgroundColor = BackgroundColor,
                ForegroundColor = ForegroundColor,
                ErrorColor = ErrorColor
            };

            if (DefaultFont != null)
            {
                copy.DefaultFont = new Font(DefaultFont.FontFamily, DefaultFont.Size, DefaultFont.Style);
            }

            return copy;
        }

        public IPrototype Clone()
        {
            return CloneTheme();
        }
    }
}