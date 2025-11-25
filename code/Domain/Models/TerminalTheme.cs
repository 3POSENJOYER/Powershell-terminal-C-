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

        public IPrototype Clone()
        {
            return new TerminalTheme
            {
                BackgroundColor = this.BackgroundColor,
                ForegroundColor = this.ForegroundColor,
                ErrorColor = this.ErrorColor,
                DefaultFont = this.DefaultFont != null ? new Font(this.DefaultFont, this.DefaultFont.Style) : null
            };
        }
    }
}