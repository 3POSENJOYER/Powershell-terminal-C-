using System.Drawing;

namespace PowerShellTerminal.Domain.Models
{
    public class TerminalTheme
    {
        public Color BackgroundColor { get; set; }
        public Color ForegroundColor { get; set; }
        public Color ErrorColor { get; set; }
        public Font DefaultFont { get; set; }
    }
}