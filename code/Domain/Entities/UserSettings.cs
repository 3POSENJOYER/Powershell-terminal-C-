namespace PowerShellTerminal.Domain.Entities
{
    public class UserSettings
    {
        public int Id { get; set; }

        public string ThemeName { get; set; } = "Default";
        public string BackgroundColor { get; set; } = "#000000";
        public string ForegroundColor { get; set; } = "#FFFFFF";

        public string FontFamily { get; set; } = "Consolas";
        public int FontSize { get; set; } = 14;

        public int WindowWidth { get; set; } = 1200;
        public int WindowHeight { get; set; } = 700;

        public string UserName { get; set; } = Environment.UserName;
        public DateTime LastModified { get; set; } = DateTime.UtcNow;
    }
}
