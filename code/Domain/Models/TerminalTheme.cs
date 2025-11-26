using System.Drawing;

namespace PowerShellTerminal.Domain.Models
{
    public class TerminalTheme
    {
        public Color BackgroundColor { get; set; }
        public Color ForegroundColor { get; set; }
        public Color ErrorColor { get; set; }
        public Font DefaultFont { get; set; }

        public TerminalTheme Clone()
        {
            return new TerminalTheme
            {
                BackgroundColor = BackgroundColor,
                ForegroundColor = ForegroundColor,
                ErrorColor = ErrorColor,
                DefaultFont = DefaultFont != null ? new Font(DefaultFont.FontFamily, DefaultFont.Size, DefaultFont.Style) : null
            };
        }
    }
}