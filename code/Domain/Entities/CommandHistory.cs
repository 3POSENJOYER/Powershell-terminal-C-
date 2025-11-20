namespace PowerShellTerminal.Domain.Entities
{
    public class CommandHistory
    {
        public int Id { get; set; }

        // Команда, яку вводить користувач
        public string Command { get; set; } = string.Empty;

        // Вивід PowerShell
        public string Output { get; set; } = string.Empty;

        // Помилки PowerShell
        public string Errors { get; set; } = string.Empty;

        // Чи успішно виконана команда
        public bool Success { get; set; }

        // Робоча директорія під час виконання
        public string WorkingDirectory { get; set; } = string.Empty;

        // Який термінальний сеанс зберіг цю команду
        public int SessionId { get; set; }

        // Час виконання
        public DateTime ExecutedAt { get; set; } = DateTime.Now;
    }
}
