Powershell Terminal (C#)
# Powershell Terminal (C# 8) — README

**Briefly:** a minimal, extensible PowerShell terminal written in **C# 8**, replicating the familiar terminal UX with customizable syntax colors, window size, background, and the ability to execute PowerShell commands and executables. Supports multiple terminal windows (tabs or splits) and implements key design patterns: **Strategy, Command, Abstract Factory, Bridge, Interpreter, Client–Server.**

---

## Contents

* Overview
* Features
* Architecture & Patterns
* Requirements
* Quick Start (build & run)

---

## Overview

This terminal is designed as both an educational and practical project.
It demonstrates:

* Integration with PowerShell (local) and command execution.
* Multi-session support via tabs or window splits.
* Syntax highlighting customization for keywords, strings, comments, etc.
* Adjustable window size, fonts, and background.
* Execution of external programs and scripts.
* A clean, modular architecture using classic design patterns.

---

## Features

* Launch local PowerShell sessions and execute commands.
* Parallel sessions: multiple tabs or split-view.
* Configurable syntax highlighting (via JSON).
* Customizable window options (size, font, background).
* Execute external `.exe` or `.ps1` files.
* Optional session logging.
* Extensible interpreter API for custom commands.

---

## Architecture & Design Patterns

| Pattern              | Usage                                                                                            |
| -------------------- | ------------------------------------------------------------------------------------------------ |
| **Strategy**         | Syntax highlighting — separate strategies for PowerShell, Bash, PlainText, etc.                  |
| **Command**          | Encapsulates user input as Command objects (with undo/redo & logging).                           |
| **Abstract Factory** | UI creation (Tab, SplitPane, Session) — allows easy switching between console and GUI renderers. |
| **Bridge**           | Separates session abstraction from rendering (e.g. `ConsoleRenderer` ↔ `GuiRenderer`).           |
| **Interpreter**      | Processes internal commands like `:split`, `:theme set dark`, etc.                               |
| **Client–Server**    | Enables remote command execution or background session handling.                                 |

See `docs/architecture.md` for detailed diagrams.

---

## Requirements

* **.NET Core 3.1+** (works with .NET 5 / 6 / 7)
* **PowerShell** (Windows PowerShell or PowerShell 7+)
* **Git** (for development)

---

## Quick Start

1. Clone the repository:

```bash
git clone https://github.com/3POSENJOYER/Powershell-terminal-C-.git
cd Powershell-terminal-C-
```

2. Build:

```bash
dotnet build
```



