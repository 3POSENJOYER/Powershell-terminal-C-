public interface ITerminalTheme
{
    System.Drawing.Color BackgroundColor { get; }
    System.Drawing.Color ForegroundColor { get; }
    System.Drawing.Color ErrorColor { get; }
    System.Drawing.Color WarningColor { get; }
    System.Drawing.Color SuccessColor { get; }
    System.Drawing.Color CommandColor { get; }
    System.Drawing.Font DefaultFont { get; }
}

public class DarkTheme : ITerminalTheme
{
    public System.Drawing.Color BackgroundColor => System.Drawing.Color.Black;
    public System.Drawing.Color ForegroundColor => System.Drawing.Color.Lime;
    public System.Drawing.Color ErrorColor => System.Drawing.Color.Red;
    public System.Drawing.Color WarningColor => System.Drawing.Color.Yellow;
    public System.Drawing.Color SuccessColor => System.Drawing.Color.Green;
    public System.Drawing.Color CommandColor => System.Drawing.Color.Cyan;
    public System.Drawing.Font DefaultFont => new System.Drawing.Font("Consolas", 10);
}

public class LightTheme : ITerminalTheme
{
    public System.Drawing.Color BackgroundColor => System.Drawing.Color.White;
    public System.Drawing.Color ForegroundColor => System.Drawing.Color.Black;
    public System.Drawing.Color ErrorColor => System.Drawing.Color.DarkRed;
    public System.Drawing.Color WarningColor => System.Drawing.Color.Orange;
    public System.Drawing.Color SuccessColor => System.Drawing.Color.DarkGreen;
    public System.Drawing.Color CommandColor => System.Drawing.Color.Blue;
    public System.Drawing.Font DefaultFont => new System.Drawing.Font("Consolas", 10);
}