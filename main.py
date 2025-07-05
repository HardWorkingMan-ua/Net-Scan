#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import ipaddress
import threading
from queue import Queue
import socket
from time import sleep
import json
import os
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, BarColumn, TimeElapsedColumn, SpinnerColumn, TaskProgressColumn
from rich.panel import Panel
from rich.columns import Columns
from rich.text import Text
from rich.live import Live
from rich.layout import Layout
from rich.tree import Tree
from rich.align import Align
from rich.rule import Rule
import pyfiglet

# Ініціалізація консолі з повною підтримкою кольорів
console = Console(force_terminal=True, color_system="truecolor")

# Глобальні змінні для статистики
scan_stats = {
    'total_hosts': 0,
    'alive_hosts': 0,
    'total_ports': 0,
    'open_ports': 0,
    'scan_time': 0,
    'vulnerabilities': 0
}

def create_gradient_text(text, colors):
    """Створює градієнтний текст з кольорової палітри"""
    result = Text()
    text_len = len(text)
    color_len = len(colors)
    
    for i, char in enumerate(text):
        color_idx = int((i / text_len) * (color_len - 1))
        result.append(char, style=colors[color_idx])
    
    return result

def print_header():
    """Виводить стильний заголовок з анімацією"""
    width = console.size.width
    height = console.size.height
    
    # Вибір шрифту залежно від розміру терміналу
    font = "slant"
    if width < 60:
        font = "mini"
    elif width > 140:
        font = "big"
    
    console.clear()
    
    # ASCII арт з градієнтом
    ascii_art = pyfiglet.figlet_format("Net-Scan", font=font)
    gradient_colors = ["bright_cyan", "cyan", "blue", "bright_blue", "magenta", "bright_magenta"]
    
    # Створюємо градієнтний заголовок
    lines = ascii_art.split('\n')
    gradient_ascii = Text()
    
    for i, line in enumerate(lines):
        if line.strip():
            color_idx = i % len(gradient_colors)
            gradient_ascii.append(line + '\n', style=gradient_colors[color_idx])
    
    # Створюємо layout
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=len(lines) + 5),
        Layout(name="info", size=8),
        Layout(name="stats", size=6)
    )
    
    # Заголовок
    header_panel = Panel(
        Align.center(gradient_ascii),
        style="bold bright_white",
        border_style="bright_yellow",
        subtitle="[bold bright_cyan]Net-scan Beta[/bold bright_cyan]",
        subtitle_align="center"
    )
    
    # Інформація про версію та автора
    info_text = Text.assemble(
        ("🚀 Версія: ", "bright_green"),
        ("1.5", "bold bright_yellow"),
        ("\n💻 Автори: ", "bright_green"),
        ("@anorthseller, @userevgeny", "bold bright_cyan"),
        ("\n🕐 Час запуску: ", "bright_green"),
        (datetime.now().strftime("%d.%m.%Y %H:%M:%S"), "bold bright_white"),
        ("\n🌟 Статус: ", "bright_green"),
        ("Готовий до сканування!", "bold bright_green")
    )
    
    info_panel = Panel(
        Align.center(info_text),
        title="[bold bright_magenta]📊 Системна Інформація[/bold bright_magenta]",
        border_style="bright_green",
        padding=(1, 2)
    )
    
    # Статистика (порожня на початку)
    stats_text = Text.assemble(
        ("📈 Відскановано хостів: ", "bright_blue"),
        ("0", "bold bright_white"),
        (" | 🎯 Живих хостів: ", "bright_blue"),
        ("0", "bold bright_green"),
        (" | 🔍 Відкритих портів: ", "bright_blue"),
        ("0", "bold bright_red"),
        (" | ⚠️ Вразливостей: ", "bright_blue"),
        ("0", "bold bright_yellow")
    )
    
    stats_panel = Panel(
        Align.center(stats_text),
        title="[bold bright_yellow]📊 Статистика Сканування[/bold bright_yellow]",
        border_style="bright_blue",
        padding=(1, 2)
    )
    
    layout["header"].update(header_panel)
    layout["info"].update(info_panel)
    layout["stats"].update(stats_panel)
    
    console.print(layout)
    console.print()

def check_internet():
    """Перевіряє підключення до інтернету з красивим індикатором"""
    with console.status("[bold bright_cyan]🌐 Перевіряю підключення до інтернету...", spinner="dots12"):
        sleep(0.5)  # Для драматичного ефекту
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "2", "8.8.8.8"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        sleep(0.5)
    
    if result.returncode == 0:
        console.print(Panel(
            "[bold bright_green]✅ Інтернет-підключення активне![/bold bright_green]\n"
            "[bright_green]📡 DNS сервер доступний[/bright_green]\n"
            "[bright_green]🚀 Готовий до сканування мережі[/bright_green]",
            title="[bold bright_green]🌐 Статус Мережі[/bold bright_green]",
            border_style="bright_green",
            padding=(1, 2)
        ))
        return True
    else:
        console.print(Panel(
            "[bold bright_red]❌ Немає підключення до інтернету![/bold bright_red]\n"
            "[bright_red]🔌 Перевірте мережеві налаштування[/bright_red]\n"
            "[bright_red]🔧 Локальне сканування може працювати[/bright_red]",
            title="[bold bright_red]🌐 Помилка Мережі[/bold bright_red]",
            border_style="bright_red",
            padding=(1, 2)
        ))
        return False

def scan_network(network_cidr):
    """Сканує мережу з красивим прогрес-баром та статистикою"""
    global scan_stats
    alive_hosts = []
    threads = []
    hosts_list = list(network_cidr.hosts())
    scan_stats['total_hosts'] = len(hosts_list)
    
    start_time = datetime.now()
    
    # Створюємо прогрес з множинними колонками
    progress = Progress(
        SpinnerColumn(style="bright_cyan"),
        "[progress.description]{task.description}",
        BarColumn(bar_width=None, complete_style="bright_green", finished_style="bright_green"),
        TaskProgressColumn(),
        "[progress.percentage]{task.percentage:>3.0f}%",
        TimeElapsedColumn(),
        console=console,
        expand=True
    )
    
    task = progress.add_task(
        f"[bold bright_cyan]🔍 Сканую мережу {network_cidr}...[/bold bright_cyan]",
        total=len(hosts_list)
    )
    
    def ping_host(host):
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "1", str(host)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if result.returncode == 0:
            alive_hosts.append(str(host))
            scan_stats['alive_hosts'] += 1
        progress.update(task, advance=1)
    
    with progress:
        for host in hosts_list:
            t = threading.Thread(target=ping_host, args=(host,))
            t.start()
            threads.append(t)
            sleep(0.01)  # Трохи затримки для стабільності
        
        for t in threads:
            t.join()
    
    scan_stats['scan_time'] = (datetime.now() - start_time).total_seconds()
    
    # Показуємо результати сканування
    if alive_hosts:
        console.print(Panel(
            f"[bold bright_green]🎯 Знайдено {len(alive_hosts)} живих хостів з {len(hosts_list)}[/bold bright_green]\n"
            f"[bright_green]⏱️ Час сканування: {scan_stats['scan_time']:.2f} секунд[/bright_green]\n"
            f"[bright_green]📊 Швидкість: {len(hosts_list)/scan_stats['scan_time']:.1f} хостів/сек[/bright_green]",
            title="[bold bright_green]📊 Результати Сканування[/bold bright_green]",
            border_style="bright_green",
            padding=(1, 2)
        ))
    else:
        console.print(Panel(
            "[bold bright_red]❌ Живих хостів не знайдено[/bold bright_red]\n"
            "[bright_red]🔍 Спробуйте іншу мережу[/bright_red]",
            title="[bold bright_red]📊 Результати Сканування[/bold bright_red]",
            border_style="bright_red",
            padding=(1, 2)
        ))
    
    return alive_hosts

def get_hostname(ip):
    """Отримує hostname з кешуванням"""
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "❓ Невідомий хост"

def grab_banner(host, port):
    """Грабить банер з порту з покращеною обробкою"""
    try:
        sock = socket.socket()
        sock.settimeout(2)
        sock.connect((host, port))
        
        if port == 80:
            sock.sendall(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
        elif port == 443:
            return "🔒 HTTPS"
        elif port == 22:
            pass  # SSH надсилає банер автоматично
        elif port == 21:
            pass  # FTP надсилає банер автоматично
        elif port == 25:
            pass  # SMTP надсилає банер автоматично
        
        banner = sock.recv(1024).decode(errors="ignore").strip()
        sock.close()
        
        if banner:
            first_line = banner.splitlines()[0]
            # Обрізаємо довгі банери
            if len(first_line) > 60:
                first_line = first_line[:60] + "..."
            return first_line
    except:
        pass
    
    # Повертаємо відомі сервіси
    common_ports = {
        21: "🗂️ FTP",
        22: "🔐 SSH",
        23: "📞 Telnet",
        25: "📧 SMTP",
        53: "🌐 DNS",
        80: "🌍 HTTP",
        110: "📬 POP3",
        143: "📮 IMAP",
        443: "🔒 HTTPS",
        993: "🔐 IMAPS",
        995: "🔐 POP3S"
    }
    
    return common_ports.get(port, "❓ Невідомий сервіс")

def check_weak_login(host, port=23):
    """Перевіряє слабкі паролі"""
    weak_combos = [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", ""),
        ("root", "root"),
        ("user", "user")
    ]
    
    for username, password in weak_combos:
        try:
            sock = socket.socket()
            sock.settimeout(3)
            sock.connect((host, port))
            
            if port == 23:  # Telnet
                sock.recv(1024)  # Читаємо привітання
                sock.sendall(f"{username}\r\n".encode())
                sleep(0.5)
                sock.sendall(f"{password}\r\n".encode())
                sleep(0.5)
                response = sock.recv(1024).decode(errors="ignore")
                sock.close()
                
                if "incorrect" not in response.lower() and "failed" not in response.lower():
                    return f"⚠️ {username}:{password}"
            
        except:
            pass
    
    return None

def scan_ports_with_services(host, port_start, port_end):
    """Сканує порти з детальною інформацією"""
    global scan_stats
    open_ports = []
    queue = Queue()
    ports = range(port_start, port_end + 1)
    scan_stats['total_ports'] += len(ports)
    
    # Створюємо прогрес з красивою анімацією
    progress = Progress(
        SpinnerColumn(style="bright_magenta"),
        "[progress.description]{task.description}",
        BarColumn(bar_width=None, complete_style="bright_magenta", finished_style="bright_magenta"),
        TaskProgressColumn(),
        "[progress.percentage]{task.percentage:>3.0f}%",
        TimeElapsedColumn(),
        console=console,
        expand=True
    )
    
    task = progress.add_task(
        f"[bold bright_magenta]🔍 Сканую порти {port_start}-{port_end} на {host}[/bold bright_magenta]",
        total=len(ports)
    )
    
    def worker():
        while True:
            port = queue.get()
            if port is None:
                break
            try:
                sock = socket.socket()
                sock.settimeout(0.5)
                sock.connect((host, port))
                service = grab_banner(host, port)
                open_ports.append((port, service))
                scan_stats['open_ports'] += 1
                sock.close()
            except:
                pass
            progress.update(task, advance=1)
            queue.task_done()
    
    threads = []
    with progress:
        # Оптимізована кількість потоків
        thread_count = min(100, len(ports))
        for _ in range(thread_count):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            threads.append(t)
        
        for port in ports:
            queue.put(port)
        
        queue.join()
        
        for _ in threads:
            queue.put(None)
        
        for t in threads:
            t.join()
    
    return open_ports

def create_host_tree(alive_hosts):
    """Створює дерево хостів для красивого відображення"""
    tree = Tree("🌐 [bold bright_cyan]Активні хости в мережі[/bold bright_cyan]")
    
    for i, host in enumerate(alive_hosts, 1):
        hostname = get_hostname(host)
        host_branch = tree.add(f"[bold bright_green]{i}. {host}[/bold bright_green]")
        host_branch.add(f"[bright_yellow]🏷️ Hostname: {hostname}[/bright_yellow]")
        host_branch.add(f"[bright_blue]📍 Статус: Онлайн[/bright_blue]")
    
    return tree

def display_port_results(host, hostname, open_ports):
    """Відображає результати сканування портів у красивому форматі"""
    if not open_ports:
        console.print(Panel(
            f"[bold bright_red]❌ Відкритих портів не знайдено на {host}[/bold bright_red]\n"
            f"[bright_red]🔒 Хост може бути захищеним фаєрволом[/bright_red]",
            title=f"[bold bright_red]🔍 Результати для {host}[/bold bright_red]",
            border_style="bright_red",
            padding=(1, 2)
        ))
        return
    
    # Створюємо таблицю для портів
    table = Table(
        title=f"🎯 [bold bright_magenta]Відкриті порти на {host}[/bold bright_magenta]",
        title_style="bold bright_magenta",
        border_style="bright_magenta",
        header_style="bold bright_white",
        show_lines=True
    )
    
    table.add_column("№", style="bright_cyan", justify="center", width=4)
    table.add_column("Порт", style="bright_yellow", justify="center", width=8)
    table.add_column("Сервіс", style="bright_green", width=20)
    table.add_column("Банер/Відповідь", style="bright_blue", width=50)
    table.add_column("Ризик", style="bright_red", justify="center", width=10)
    
    for i, (port, service) in enumerate(open_ports, 1):
        # Визначаємо рівень ризику
        risk_level = "🟢 Низький"
        if port in [21, 23, 135, 139, 445]:
            risk_level = "🔴 Високий"
        elif port in [22, 80, 443]:
            risk_level = "🟡 Середній"
        
        table.add_row(
            str(i),
            str(port),
            service.split()[0] if service else "❓",
            service,
            risk_level
        )
    
    console.print(table)
    
    # Перевіряємо на слабкі паролі
    if any(port in [21, 22, 23] for port, _ in open_ports):
        console.print(Panel(
            "[bold bright_yellow]🔍 Перевіряю на слабкі паролі...[/bold bright_yellow]",
            border_style="bright_yellow"
        ))
        
        for port, _ in open_ports:
            if port in [21, 22, 23]:
                weak_creds = check_weak_login(host, port)
                if weak_creds:
                    scan_stats['vulnerabilities'] += 1
                    console.print(Panel(
                        f"[bold bright_red]⚠️ ВРАЗЛИВІСТЬ ЗНАЙДЕНА![/bold bright_red]\n"
                        f"[bright_red]🎯 Хост: {host}[/bright_red]\n"
                        f"[bright_red]🔓 Порт: {port}[/bright_red]\n"
                        f"[bright_red]🔑 Креди: {weak_creds}[/bright_red]\n"
                        f"[bright_red]⚠️ Рекомендується змінити пароль![/bright_red]",
                        title="[bold bright_red]🚨 КРИТИЧНА ВРАЗЛИВІСТЬ[/bold bright_red]",
                        border_style="bright_red",
                        padding=(1, 2)
                    ))

def show_advanced_menu():
    """Показує розширене меню з опціями"""
    menu_options = [
        ("1", "📡", "Швидке сканування", "Пінг мережі 192.168.1.0/24"),
        ("2", "🔍", "Глибоке сканування", "Сканування + порти (1-1000)"),
        ("3", "⚙️", "Налаштування", "Кастомне сканування"),
        ("4", "🎯", "Цільове сканування", "Сканування конкретного хоста"),
        ("5", "📊", "Статистика", "Поточна статистика сканування"),
        ("6", "💾", "Експорт", "Зберегти результати"),
        ("0", "🚪", "Вихід", "Завершити роботу")
    ]
    
    console.print(Rule("[bold bright_cyan]🎮 Головне Меню[/bold bright_cyan]", style="bright_cyan"))
    console.print()
    
    # Створюємо сітку з опціями
    panels = []
    for option, icon, title, desc in menu_options:
        color = "bright_green" if option != "0" else "bright_red"
        panels.append(Panel(
            f"[bold {color}]{icon}[/bold {color}]\n"
            f"[bold bright_white]{title}[/bold bright_white]\n"
            f"[dim bright_white]{desc}[/dim bright_white]",
            title=f"[bold {color}]{option}[/bold {color}]",
            border_style=color,
            padding=(1, 1),
            width=25
        ))
    
    # Відображаємо в колонках
    console.print(Columns(panels[:4], equal=True, expand=True))
    console.print()
    console.print(Columns(panels[4:], equal=True, expand=True))
    console.print()
    
    choice = console.input("[bold bright_yellow]🎯 Оберіть опцію: [/bold bright_yellow]")
    return choice.strip()

def show_statistics():
    """Показує детальну статистику сканування"""
    stats_table = Table(
        title="📊 [bold bright_cyan]Статистика Сканування[/bold bright_cyan]",
        border_style="bright_cyan",
        header_style="bold bright_white",
        show_lines=True
    )
    
    stats_table.add_column("Параметр", style="bright_yellow", width=25)
    stats_table.add_column("Значення", style="bright_green", width=20)
    stats_table.add_column("Деталі", style="bright_blue", width=30)
    
    stats_table.add_row(
        "🎯 Відскановано хостів",
        str(scan_stats['total_hosts']),
        f"IP адреси в мережі"
    )
    
    stats_table.add_row(
        "✅ Живих хостів",
        str(scan_stats['alive_hosts']),
        f"{scan_stats['alive_hosts']/max(scan_stats['total_hosts'], 1)*100:.1f}% від загальної кількості"
    )
    
    stats_table.add_row(
        "🔍 Перевірено портів",
        str(scan_stats['total_ports']),
        f"Всього TCP портів"
    )
    
    stats_table.add_row(
        "🔓 Відкритих портів",
        str(scan_stats['open_ports']),
        f"{scan_stats['open_ports']/max(scan_stats['total_ports'], 1)*100:.1f}% від перевірених"
    )
    
    stats_table.add_row(
        "⚠️ Вразливостей",
        str(scan_stats['vulnerabilities']),
        f"Знайдено слабких паролів"
    )
    
    stats_table.add_row(
        "⏱️ Час сканування",
        f"{scan_stats['scan_time']:.2f} сек",
        f"Загальний час виконання"
    )
    
    console.print(stats_table)

def save_results_to_file(results, filename=None):
    """Зберігає результати сканування у файл"""
    if filename is None:
        filename = f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    # Перетворюємо IPv4Network об'єкти на рядки
    serializable_results = []
    for item in results:
        scan_type, target, data = item
        
        # Якщо target - це мережа, перетворюємо на рядок
        if isinstance(target, ipaddress.IPv4Network):
            target = str(target)
        
        serializable_results.append((scan_type, target, data))
    
    scan_data = {
        'timestamp': datetime.now().isoformat(),
        'statistics': scan_stats,
        'results': serializable_results
    }
    
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(scan_data, f, indent=2, ensure_ascii=False)
        
        console.print(Panel(
            f"[bold bright_green]✅ Результати збережено![/bold bright_green]\n"
            f"[bright_green]📁 Файл: {filename}[/bright_green]\n"
            f"[bright_green]📊 Розмір: {os.path.getsize(filename)} байт[/bright_green]",
            title="[bold bright_green]💾 Експорт Завершено[/bold bright_green]",
            border_style="bright_green",
            padding=(1, 2)
        ))
        return True
    except Exception as e:
        console.print(Panel(
            f"[bold bright_red]❌ Помилка збереження![/bold bright_red]\n"
            f"[bright_red]📁 Файл: {filename}[/bright_red]\n"
            f"[bright_red]🚫 Помилка: {str(e)}[/bright_red]",
            title="[bold bright_red]💾 Помилка Експорту[/bold bright_red]",
            border_style="bright_red",
            padding=(1, 2)
        ))
        return False

def main():
    """Головна функція програми"""
    print_header()
    
    # Перевіряємо інтернет
    if not check_internet():
        console.input("\n[bold bright_yellow]⏸️ Натисніть Enter для продовження...[/bold bright_yellow]")
    
    results_history = []
    
    while True:
        choice = show_advanced_menu()
        
        if choice == "0":
            console.print(Panel(
                "[bold bright_magenta]👋 Дякуємо за використання Net-Scan![/bold bright_magenta]\n"
                "[bright_magenta]🚀 До побачення![/bright_magenta]",
                title="[bold bright_magenta]🚪 Завершення Роботи[/bold bright_magenta]",
                border_style="bright_magenta",
                padding=(1, 2)
            ))
            break
            
        elif choice == "1":
            # Швидке сканування
            network_cidr = ipaddress.ip_network("192.168.1.0/24")
            alive_hosts = scan_network(network_cidr)
            
            if alive_hosts:
                results_history.append(('ping', network_cidr, alive_hosts))
                tree = create_host_tree(alive_hosts)
                console.print(tree)
            
        elif choice == "2":
            # Глибоке сканування
            network_cidr = ipaddress.ip_network("192.168.1.0/24")
            alive_hosts = scan_network(network_cidr)
            
            if alive_hosts:
                results_history.append(('deep_scan', network_cidr, alive_hosts))
                for host in alive_hosts:
                    hostname = get_hostname(host)
                    open_ports = scan_ports_with_services(host, 1, 1000)
                    display_port_results(host, hostname, open_ports)
                    console.print()
            
        elif choice == "3":
            # Налаштування
            try:
                cidr_str = console.input(
                    "[bold bright_yellow]🌐 Введіть CIDR мережі (наприклад, 192.168.1.0/24): [/bold bright_yellow]"
                ).strip()
                
                port_start = int(console.input(
                    "[bold bright_yellow]🔍 Початковий порт (наприклад, 1): [/bold bright_yellow]"
                ))
                
                port_end = int(console.input(
                    "[bold bright_yellow]🔍 Кінцевий порт (наприклад, 1000): [/bold bright_yellow]"
                ))
                
                network_cidr = ipaddress.ip_network(cidr_str)
                alive_hosts = scan_network(network_cidr)
                
                if alive_hosts:
                    results_history.append(('custom_scan', network_cidr, alive_hosts))
                    for host in alive_hosts:
                        hostname = get_hostname(host)
                        open_ports = scan_ports_with_services(host, port_start, port_end)
                        display_port_results(host, hostname, open_ports)
                        console.print()
                        
            except ValueError as e:
                console.print(Panel(
                    f"[bold bright_red]❌ Некоректні дані![/bold bright_red]\n"
                    f"[bright_red]🚫 Помилка: {str(e)}[/bright_red]",
                    title="[bold bright_red]🚨 Помилка Введення[/bold bright_red]",
                    border_style="bright_red"
                ))
            except Exception as e:
                console.print(Panel(
                    f"[bold bright_red]❌ Непередбачена помилка![/bold bright_red]\n"
                    f"[bright_red]🚫 Деталі: {str(e)}[/bright_red]",
                    title="[bold bright_red]🚨 Системна Помилка[/bold bright_red]",
                    border_style="bright_red"
                ))
        
        elif choice == "4":
            # Цільове сканування
            try:
                target_ip = console.input(
                    "[bold bright_yellow]🎯 Введіть IP адресу для сканування: [/bold bright_yellow]"
                ).strip()
                
                # Валідація IP
                ipaddress.ip_address(target_ip)
                
                console.print(Panel(
                    f"[bold bright_cyan]🔍 Сканую цільовий хост {target_ip}...[/bold bright_cyan]",
                    border_style="bright_cyan"
                ))
                
                # Перевіряємо доступність
                result = subprocess.run(
                    ["ping", "-c", "3", "-W", "2", target_ip],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                
                if result.returncode == 0:
                    hostname = get_hostname(target_ip)
                    console.print(Panel(
                        f"[bold bright_green]✅ Хост {target_ip} доступний![/bold bright_green]\n"
                        f"[bright_green]🏷️ Hostname: {hostname}[/bright_green]",
                        title="[bold bright_green]🎯 Цільовий Хост[/bold bright_green]",
                        border_style="bright_green"
                    ))
                    
                    # Сканування портів
                    open_ports = scan_ports_with_services(target_ip, 1, 65535)
                    display_port_results(target_ip, hostname, open_ports)
                    
                    results_history.append(('target_scan', target_ip, [(target_ip, open_ports)]))
                else:
                    console.print(Panel(
                        f"[bold bright_red]❌ Хост {target_ip} недоступний![/bold bright_red]\n"
                        f"[bright_red]🔒 Можливо хост вимкнений або заблокований[/bright_red]",
                        title="[bold bright_red]🎯 Цільовий Хост[/bold bright_red]",
                        border_style="bright_red"
                    ))
                    
            except ValueError:
                console.print(Panel(
                    "[bold bright_red]❌ Некоректна IP адреса![/bold bright_red]\n"
                    "[bright_red]📝 Формат: 192.168.1.1[/bright_red]",
                    title="[bold bright_red]🚨 Помилка Введення[/bold bright_red]",
                    border_style="bright_red"
                ))
            except Exception as e:
                console.print(Panel(
                    f"[bold bright_red]❌ Помилка сканування![/bold bright_red]\n"
                    f"[bright_red]🚫 Деталі: {str(e)}[/bright_red]",
                    title="[bold bright_red]🚨 Помилка Сканування[/bold bright_red]",
                    border_style="bright_red"
                ))
        
        elif choice == "5":
            # Статистика
            show_statistics()
            
        elif choice == "6":
            # Експорт результатів
            if not results_history:
                console.print(Panel(
                    "[bold bright_yellow]⚠️ Немає результатів для експорту![/bold bright_yellow]\n"
                    "[bright_yellow]🔍 Виконайте спочатку сканування[/bright_yellow]",
                    title="[bold bright_yellow]💾 Експорт Результатів[/bold bright_yellow]",
                    border_style="bright_yellow"
                ))
            else:
                filename = console.input(
                    "[bold bright_yellow]📁 Введіть ім'я файлу (або Enter для авто): [/bold bright_yellow]"
                ).strip()
                
                if not filename:
                    filename = None
                
                save_results_to_file(results_history, filename)
        
        else:
            console.print(Panel(
                "[bold bright_red]❌ Невірний вибір![/bold bright_red]\n"
                "[bright_red]🔢 Оберіть число від 0 до 6[/bright_red]",
                title="[bold bright_red]🚨 Помилка Меню[/bold bright_red]",
                border_style="bright_red"
            ))
        
        # Пауза перед наступною ітерацією
        console.print()
        console.input("[bold bright_white]⏸️ Натисніть Enter для продовження...[/bold bright_white]")
        console.clear()
        print_header()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print()
        console.print(Panel(
            "[bold bright_yellow]⚠️ Переривання користувачем![/bold bright_yellow]\n"
            "[bright_yellow]👋 Програма завершена через Ctrl+C[/bright_yellow]",
            title="[bold bright_yellow]⚡ Екстрене Завершення[/bold bright_yellow]",
            border_style="bright_yellow",
            padding=(1, 2)
        ))
    except Exception as e:
        console.print(Panel(
            f"[bold bright_red]💥 Критична помилка![/bold bright_red]\n"
            f"[bright_red]🚫 Деталі: {str(e)}[/bright_red]\n"
            f"[bright_red]📧 Повідомте про помилку розробнику[/bright_red]",
            title="[bold bright_red]🚨 Системна Помилка[/bold bright_red]",
            border_style="bright_red",
            padding=(1, 2)
        ))
    finally:
        console.print("[bold bright_cyan]👋 До побачення![/bold bright_cyan]")
