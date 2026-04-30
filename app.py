import customtkinter as ctk
import threading
import queue
import socket
import requests
import whois
import sys
import os
import tkinter as tk
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup


ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

log_queue = queue.Queue()

current_url = "-"
crawled_url = "-"
visited_count = 0
max_estimated = 1

stop_flag = False


def log(msg):
    log_queue.put(msg)


def set_current(url):
    global current_url
    current_url = url


def set_crawled(url):
    global crawled_url, visited_count
    crawled_url = url
    visited_count += 1
    log(f"CRAWLED: {url}")


def restart_app():
    python = sys.executable
    os.execl(python, python, *sys.argv)


def stop_and_restart():
    log("STOP -> RESTARTING APP")
    restart_app()


def crawl(domain, depth):
    global stop_flag, visited_count, max_estimated

    stop_flag = False
    visited_count = 0
    max_estimated = 50 * depth

    domain = domain.replace("http://", "").replace("https://", "").replace("www.", "")

    visited = set()

    def crawl_page(url, d):
        global stop_flag

        if stop_flag:
            return

        if d > depth:
            return

        if url in visited:
            return

        visited.add(url)

        try:
            set_current(url)
            set_crawled(url)

            r = requests.get(url, timeout=5)
            soup = BeautifulSoup(r.text, "html.parser")

            for a in soup.find_all("a", href=True):
                href = a["href"]

                if href.startswith(("mailto:", "tel:", "javascript:", "#")):
                    continue

                next_url = urljoin(url, href)
                netloc = urlparse(next_url).netloc.replace("www.", "")

                if domain not in netloc:
                    continue

                crawl_page(next_url, d + 1)

        except Exception as e:
            log(f"ERROR: {e}")

    start_url = f"https://{domain}"
    crawl_page(start_url, 0)


def scan(domain, robots, depth):
    global max_estimated, visited_count

    visited_count = 0
    max_estimated = 50 * depth

    domain = domain.strip().replace("http://", "").replace("https://", "").replace("www.", "")

    try:
        ip = socket.gethostbyname(domain)
        log(f"IP: {ip}")

        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = r.json()

        if data.get("status") == "success":
            log(f"LOCATION: {data.get('country')} / {data.get('city')}")
            log(f"ISP: {data.get('isp')}")

    except Exception as e:
        log(f"IP ERROR: {e}")

    try:
        w = whois.whois(domain)
        log(f"WHOIS: {w.registrar}")

    except Exception as e:
        log(f"WHOIS ERROR: {e}")

    if robots:
        try:
            r = requests.get(f"https://{domain}/robots.txt", timeout=5)
            if r.status_code == 200:
                log(r.text[:500])
        except:
            pass

    crawl(f"https://{domain}", depth)


def start_scan(domain, robots, depth):
    threading.Thread(target=scan, args=(domain, robots, depth), daemon=True).start()


class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        # ================= WINDOW =================
        self.title("WANALYZER")
        self.geometry("1050x800")
        self.minsize(1050, 800)

        # ================= ICON (KALI FIX) =================
        try:
            self.icon = tk.PhotoImage(file="icon.png")
            self.iconphoto(True, self.icon)
        except Exception as e:
            print(f"Icon error: {e}")

        # ================= UI =================
        self.title_label = ctk.CTkLabel(
            self,
            text="WANALYZER",
            font=("Consolas", 26),
            text_color="#00ff88"
        )
        self.title_label.pack(pady=10)

        self.domain_entry = ctk.CTkEntry(self, width=650, placeholder_text="domain")
        self.domain_entry.pack(pady=10)

        self.robots_var = ctk.BooleanVar(value=True)
        self.robots_check = ctk.CTkCheckBox(self, text="robots.txt", variable=self.robots_var)
        self.robots_check.pack()

        self.depth_label = ctk.CTkLabel(self, text="Crawl depth: 2", text_color="#00ff88")
        self.depth_label.pack()

        self.depth_slider = ctk.CTkSlider(self, from_=1, to=5, number_of_steps=4, command=self.update_depth)
        self.depth_slider.set(2)
        self.depth_slider.pack(pady=5)

        self.current_label = ctk.CTkLabel(self, text="Now crawling: -", text_color="#00ff88")
        self.current_label.pack()

        self.crawled_label = ctk.CTkLabel(self, text="CRAWLED: -", text_color="#00ff88")
        self.crawled_label.pack()

        self.progress = ctk.CTkProgressBar(self, progress_color="#00ff88")
        self.progress.set(0)
        self.progress.pack(pady=10, fill="x", padx=20)

        self.start_btn = ctk.CTkButton(self, text="START", command=self.start)
        self.start_btn.pack(pady=5)

        self.stop_btn = ctk.CTkButton(self, text="STOP (RESTART)", fg_color="red", command=stop_and_restart)
        self.stop_btn.pack(pady=5)

        self.clear_btn = ctk.CTkButton(self, text="CLEAR", command=self.clear)
        self.clear_btn.pack(pady=5)

        self.save_btn = ctk.CTkButton(self, text="SAVE", command=self.save)
        self.save_btn.pack(pady=5)

        self.exit_btn = ctk.CTkButton(self, text="CLOSE", fg_color="gray", command=self.destroy)
        self.exit_btn.pack(pady=5)

        self.log_box = ctk.CTkTextbox(self, width=1000, height=450, font=("Consolas", 12))
        self.log_box.pack(pady=10)

        self.after(100, self.update_ui)

    def update_depth(self, value):
        self.depth_label.configure(text=f"Crawl depth: {int(float(value))}")

    def start(self):
        domain = self.domain_entry.get()
        depth = int(self.depth_slider.get())
        self.log_box.insert("end", f"\nSTART {domain}\n")
        start_scan(domain, self.robots_var.get(), depth)

    def clear(self):
        self.log_box.delete("1.0", "end")

    def save(self):
        with open("recon_log.txt", "w", encoding="utf-8") as f:
            f.write(self.log_box.get("1.0", "end"))

    def update_ui(self):
        while not log_queue.empty():
            msg = log_queue.get()
            self.log_box.insert("end", msg + "\n")
            self.log_box.see("end")

        self.current_label.configure(text=f"Now crawling: {current_url}")
        self.crawled_label.configure(text=f"CRAWLED: {crawled_url}")

        if max_estimated > 0:
            self.progress.set(min(visited_count / max_estimated, 1))

        self.after(100, self.update_ui)


if __name__ == "__main__":
    app = App()
    app.mainloop()
