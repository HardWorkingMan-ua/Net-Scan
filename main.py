import subprocess
import ipaddress
import threading
from queue import Queue
import socket
from time import sleep
from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.progress import Progress, BarColumn, TimeElapsedColumn, SpinnerColumn
import pyfiglet
from rich.panel import Panel

console = Console()

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
    width = console.size.width
    font = "slant"
    if width < 50:
        font = "mini"
    elif width > 120:
        font = "big"

    ascii_art = pyfiglet.figlet_format("Net-Scan", font=font)
    gradient_colors = ["bright_cyan", "cyan", "blue", "bright_blue", "magenta", "bright_magenta"]
    
    # Створюємо градієнтний заголовок
    lines = ascii_art.split('\n')
    gradient_ascii = Text()
    
    for i, line in enumerate(lines):
        if line.strip():
            color_idx = i % len(gradient_colors)
            gradient_ascii.append(line + '\n', style=gradient_colors[color_idx])

    footer = Text("\nby @anorthseller", style="bold cyan")
    combined = gradient_ascii + footer  # Тепер обидва — Text

    panel = Panel(
        combined,
        style="bold green",
        expand=(width > 50),
        border_style="magenta"
    )
    console.clear()
    console.print(panel)

def check_internet():
    result = subprocess.run(
        ["ping", "-c", "1", "-W", "2", "google.com"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return result.returncode == 0

def scan_network(network_cidr):
    alive_hosts = []
    threads = []
    hosts_list = list(network_cidr.hosts())

    progress = Progress(
        SpinnerColumn(),
        "[progress.description]{task.description}",
        BarColumn(),
        "[progress.percentage]{task.percentage:>3.0f}%",
        TimeElapsedColumn()
    )
    task = progress.add_task(
        "Пінгуємо IP...",
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
        progress.update(task, advance=1)

    with progress:
        for host in hosts_list:
            t = threading.Thread(target=ping_host, args=(host,))
            t.start()
            threads.append(t)
            sleep(0.005)
        for t in threads:
            t.join()
    return alive_hosts

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "N/A"

def grab_banner(host, port):
    try:
        sock = socket.socket()
        sock.settimeout(2)
        sock.connect((host, port))
        
        if port in (80, 8080):
            sock.sendall(b"GET / HTTP/1.0\r\n\r\n")
        elif port == 21:  # FTP
            # просто чекаємо банер після підключення
            pass
        elif port == 22:  # SSH
            # сервер повинен надіслати банер сам
            pass
        elif port == 25:  # SMTP
            # сервер надсилає банер
            pass
        elif port == 23:  # Telnet
            # сервер може послати банер
            pass

        banner = sock.recv(1024).decode(errors="ignore").strip()
        sock.close()

        if banner:
            first_line = banner.splitlines()[0]
            return first_line
    except Exception as e:
        # Можна додати лог, наприклад: print(f"Banner error on {host}:{port} - {e}")
        pass
    return "N/A"


def check_weak_login(host, port=23):
    try:
        sock = socket.socket()
        sock.settimeout(2)
        sock.connect((host, port))
        sock.sendall(b"admin\r\n")
        sock.sendall(b"admin\r\n")
        response = sock.recv(1024).decode(errors="ignore")
        sock.close()
        if "incorrect" not in response.lower():
            return True
    except:
        pass
    return False

def scan_ports_with_services(host, port_start, port_end):
    open_ports = []
    queue = Queue()
    ports = range(port_start, port_end + 1)

    progress = Progress(
        SpinnerColumn(),
        "[progress.description]{task.description}",
        BarColumn(),
        "[progress.percentage]{task.percentage:>3.0f}%",
        TimeElapsedColumn()
    )
    task = progress.add_task(
        f"Скануємо порти {port_start}-{port_end} на {host}",
        total=len(ports)
    )

    def worker():
        while True:
            port = queue.get()
            if port is None:
                break
            try:
                sock = socket.socket()
                sock.settimeout(0.3)
                sock.connect((host, port))
                service = grab_banner(host, port)
                open_ports.append((port, service))
                sock.close()
            except:
                pass
            progress.update(task, advance=1)
            queue.task_done()

    threads = []
    with progress:
        for _ in range(50):
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

def menu():
    width = console.size.width
    menu_panel = Panel(
        "[bold cyan]📋 Що будемо робити?[/bold cyan]\n\n"
        "[green][1][/green] 📡 [bold]Пінг мережі[/bold]\n"
        "[green][2][/green] 🔍 [bold]Скан + порти (1-15000)[/bold]\n"
        "[green][3][/green] ⚙️ [bold]Скан з налаштуваннями[/bold]\n"
        "[red][0][/red] 🚪 [bold]Вихід[/bold]",
        title="[bold green]Меню[/bold green]",
        border_style="blue",
        expand=(width > 50)
    )
    console.print(menu_panel)
    choice = console.input("[bold yellow]🔷 Твій вибір: [/bold yellow]")
    return choice.strip()

def main():
    if not check_internet():
        console.print(
            Panel("[bold red]❌ Інтернету немає! Перевір підключення.[/bold red]", border_style="red")
        )
        return

    console.print(
        Panel("[bold green]✅ Інтернет працює! Продовжуємо…[/bold green]", border_style="green")
    )

    while True:
        choice = menu()
        if choice == "0":
            console.print(Panel("[bold magenta]👋 Вихід...[/bold magenta]", border_style="magenta"))
            break
        elif choice == "1":
            network_cidr = ipaddress.ip_network("192.168.1.0/24")
            alive_hosts = scan_network(network_cidr)

            table = Table(
                title="🎯 [bold yellow]Живі хости[/bold yellow]",
                border_style="green"
            )
            table.add_column("№", justify="right", style="cyan", no_wrap=True)
            table.add_column("IP", style="green", no_wrap=True)

            for idx, host in enumerate(alive_hosts, 1):
                table.add_row(str(idx), host)

            console.print(table)

        elif choice == "2":
            network_cidr = ipaddress.ip_network("192.168.1.0/24")
            alive_hosts = scan_network(network_cidr)

            for idx, host in enumerate(alive_hosts, 1):
                console.print(
                    Panel(f"[bold green]{idx}. Сканую порти 1-15000 на {host}…[/bold green]", border_style="cyan")
                )
                open_ports = scan_ports_with_services(host, 1, 15000)

                if open_ports:
                    table = Table(
                        title=f"🎯 [bold]Відкриті порти на {host}[/bold]",
                        border_style="bright_magenta"
                    )
                    table.add_column("Порт", style="cyan", justify="right")
                    table.add_column("Сервіс/Банер", style="magenta")

                    for port, service in open_ports:
                        table.add_row(str(port), service)

                    console.print(table)
                else:
                    console.print(
                        Panel(f"[red]❌ Відкритих портів на {host} не знайдено[/red]", border_style="red")
                    )

        elif choice == "3":
            cidr_str = console.input("[yellow]Введи мережу (CIDR, напр. 192.168.1.0/24): [/yellow]").strip()
            port_start = int(console.input("[yellow]Початковий порт: [/yellow]"))
            port_end = int(console.input("[yellow]Кінцевий порт: [/yellow]"))
            network_cidr = ipaddress.ip_network(cidr_str)

            alive_hosts = scan_network(network_cidr)

            for idx, host in enumerate(alive_hosts, 1):
                hostname = get_hostname(host)
                console.print(
                    Panel(f"[bold green]{idx}. Сканую порти на {host} ({hostname})…[/bold green]", border_style="cyan")
                )
                open_ports = scan_ports_with_services(host, port_start, port_end)

                if open_ports:
                    table = Table(
                        title=f"🎯 {host} ({hostname})",
                        border_style="bright_magenta"
                    )
                    table.add_column("Порт", style="cyan")
                    table.add_column("Сервіс/Банер", style="magenta")
                    for port, service in open_ports:
                        table.add_row(str(port), service)
                    console.print(table)

                    if check_weak_login(host):
                        console.print(
                            Panel(f"[bold red]⚠️ Слабкий логін admin:admin знайдено на {host}[/bold red]", border_style="red")
                        )
                else:
                    console.print(
                        Panel(f"[bold red]Відкритих портів не знайдено на {host}[/bold red]", border_style="red")
                    )

        else:
            console.print(Panel("[bold red]Невірний вибір, спробуй ще раз.[/bold red]", border_style="red"))

print_header()

if __name__ == "__main__":
    main()
