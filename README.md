# YARA File Scanner 🛡️

[🇺🇦 Українська](#україна) | [🇬🇧 English](#english)

---

<a name="україна"></a>
## 🇺🇦 Опис проєкту

**YARA File Scanner** — це легкий та модульний CLI-інструмент для сигнатурного аналізу файлової системи та пошуку потенційних загроз (малварі, інфостилерів, веб-шелів, підозрілих скриптів) за допомогою **YARA** та **Python**.

Проєкт створений як практичний інструмент для початківців у кібербезпеці (Junior SOC / Incident Response) для автоматизації перевірки індикаторів компрометації (IoC).

### 🚀 Основні можливості

* **Модульна структура правил:** кожне YARA-правило зберігається в окремому файлі в папці `rules/`.
* **Динамічна компіляція:** скрипт автоматично збирає всі `.yar` та `.yara` файли з папки правил і компілює їх в єдиний об'єкт.
* **Рекурсивне сканування:** обходить усі вкладені директорії за допомогою `os.walk`.
* **Зручний CLI:** інтерфейс на базі `argparse` для вибору цільової та правил-директорій.
* **Детальні сповіщення:** виводить шлях до файлу, спрацьоване правило та знайдені патерни.
* **Безпечна обробка помилок:** файли без доступу або заблоковані системою пропускаються без зупинки сканування.
* **Підсумкова статистика:** кількість перевірених та підозрілих файлів після завершення.

### 📁 Структура проєкту

```text
yara-file-scanner/
├── script.py        # Основний скрипт сканера
├── rules/           # YARA-правила (.yar / .yara)
│   ├── powershell_obfuscation.yar
│   ├── ransomware.yar
│   ├── webshell.yar
│   └── ...
└── README.md
```

### 📦 Встановлення

1. Клонуйте репозиторій:
```bash
   git clone https://github.com/your-username/yara-file-scanner.git
   cd yara-file-scanner
```

2. Встановіть залежності:
```bash
   pip install yara-python
```

3. Переконайтеся, що YARA-правила лежать у папці `rules/` з розширенням `.yar` або `.yara`.

> **Вимоги:** Python 3.7+ та бібліотека `yara-python`.

### ⚙️ Використання

Вкажіть директорію для сканування через `-d` / `--directory`:

```bash
# Windows
python script.py -d C:\path\to\target_dir

# Linux / macOS
python3 script.py -d /path/to/target_dir
```

**Параметри:**

| Параметр | Опис | Обов'язковий |
|---|---|---|
| `-d`, `--directory` | Директорія для сканування | ✅ Так |
| `-r`, `--rules` | Папка з YARA-правилами (за замовчуванням: `rules`) | ❌ Ні |
| `-h`, `--help` | Показати довідку | ❌ Ні |

**Приклад з власною папкою правил:**

```bash
python script.py -d ./samples -r ./my_rules
```

### 🖥️ Приклад виводу

```text
[*] Found 10 rule file(s). Compiling YARA rules...
[+] Compilation successful!

[*] Starting scan on directory: './samples'...
==================================================
[!] ALERT: Suspicious file detected -> ./samples/test.ps1
    [>] Triggered Rule: PowerShell_Obfuscation
    [>] Matched Patterns: {'-EncodedCommand', 'FromBase64String'}
--------------------------------------------------
==================================================
[*] Scan completed.
    - Total files scanned: 42
    - Suspicious files found: 1
```

### ⚠️ Застереження

Інструмент призначений для навчання та легального аналізу. Використовуйте його лише на системах, на сканування яких маєте дозвіл. Сигнатурний аналіз не замінює повноцінний антивірус чи EDR і може давати хибнопозитивні спрацьовування.

---

<a name="english"></a>
## 🇬🇧 Project Description

**YARA File Scanner** is a lightweight and modular CLI tool for signature-based file system analysis and threat hunting (malware, infostealers, web shells, suspicious scripts) built on **YARA** and **Python**.

It is designed as a practical tool for cybersecurity beginners (Junior SOC / Incident Response) to automate the checking of Indicators of Compromise (IoCs).

### 🚀 Key Features

* **Modular Rule Structure:** each YARA rule lives in a separate file inside the `rules/` directory.
* **Dynamic Compilation:** the script automatically collects all `.yar` and `.yara` files from the rules folder and compiles them into a single object.
* **Recursive Scanning:** walks through all nested directories using `os.walk`.
* **User-Friendly CLI:** `argparse`-based interface for choosing the target and rules directories.
* **Detailed Alerts:** prints the file path, the triggered rule, and the matched patterns.
* **Robust Error Handling:** safely skips locked or inaccessible files without interrupting the scan.
* **Scan Summary:** reports the number of scanned and suspicious files when finished.

### 📁 Project Structure

```text
yara-file-scanner/
├── script.py        # Main scanner script
├── rules/           # YARA rules (.yar / .yara)
│   ├── powershell_obfuscation.yar
│   ├── ransomware.yar
│   ├── webshell.yar
│   └── ...
└── README.md
```

### 📦 Installation

1. Clone the repository:
```bash
   git clone https://github.com/your-username/yara-file-scanner.git
   cd yara-file-scanner
```

2. Install dependencies:
```bash
   pip install yara-python
```

3. Make sure your YARA rules are placed in the `rules/` folder with a `.yar` or `.yara` extension.

> **Requirements:** Python 3.7+ and the `yara-python` library.

### ⚙️ Usage

Specify the directory to scan with `-d` / `--directory`:

```bash
# Windows
python script.py -d C:\path\to\target_dir

# Linux / macOS
python3 script.py -d /path/to/target_dir
```

**Arguments:**

| Argument | Description | Required |
|---|---|---|
| `-d`, `--directory` | Directory to scan | ✅ Yes |
| `-r`, `--rules` | Folder with YARA rules (default: `rules`) | ❌ No |
| `-h`, `--help` | Show help message | ❌ No |

**Example with a custom rules folder:**

```bash
python script.py -d ./samples -r ./my_rules
```

### 🖥️ Example Output

```text
[*] Found 10 rule file(s). Compiling YARA rules...
[+] Compilation successful!

[*] Starting scan on directory: './samples'...
==================================================
[!] ALERT: Suspicious file detected -> ./samples/test.ps1
    [>] Triggered Rule: PowerShell_Obfuscation
    [>] Matched Patterns: {'-EncodedCommand', 'FromBase64String'}
--------------------------------------------------
==================================================
[*] Scan completed.
    - Total files scanned: 42
    - Suspicious files found: 1
```

### ⚠️ Disclaimer

This tool is intended for educational purposes and lawful analysis. Only scan systems you are authorized to inspect. Signature-based detection is not a replacement for a full antivirus/EDR solution and may produce false positives.

---

## 🛡️ License / Ліцензія

This project is open-source and available under the [MIT License](LICENSE).
Проєкт має відкритий вихідний код і поширюється за ліцензією [MIT](LICENSE).