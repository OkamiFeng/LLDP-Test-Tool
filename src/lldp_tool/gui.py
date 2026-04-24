from __future__ import annotations

import queue
import threading
import tkinter as tk
from datetime import datetime
from tkinter import messagebox, scrolledtext, ttk

from .adapters import format_adapter_label
from .hexutil import HexParseError, format_hex, parse_hex_bytes
from .input_packets import InputMode, build_packet_from_input
from .models import AdapterInfo, PacketBytes
from .npcap import (
    detect_npcap_status,
    find_bundled_npcap_installer,
    is_running_as_admin,
    launch_npcap_installer,
)
from .packets import PacketBuildError
from .scapy_io import ScapyLldpRuntime, ScapyRuntimeError


APP_TITLE = "LLDPバイト送受信ツール"


def format_received_packet(
    packet: PacketBytes,
    adapter_name: str,
    received_at: datetime,
) -> str:
    return (
        f"受信時刻: {received_at:%Y-%m-%d %H:%M:%S}\n"
        f"インターフェース: {adapter_name}\n"
        f"送信元MAC: {packet.src_mac}\n"
        f"宛先MAC: {packet.dst_mac}\n"
        f"EtherType: 0x{packet.ethertype:04X}\n"
        f"Ethernet Frame:\n{format_hex(packet.full_frame)}\n"
        f"LLDPDU:\n{format_hex(packet.lldpdu)}\n"
        "----\n"
    )


class LldpToolApp(tk.Tk):
    def __init__(self, runtime: ScapyLldpRuntime | None = None):
        super().__init__()
        self.title(APP_TITLE)
        self.minsize(980, 720)

        self.runtime = runtime or ScapyLldpRuntime()
        self.adapters: list[AdapterInfo] = []
        self.receiver_stop = threading.Event()
        self.receiver_thread: threading.Thread | None = None
        self.event_queue: queue.Queue[tuple[str, object]] = queue.Queue()

        self.npcap_var = tk.StringVar(value="Npcap 状態を確認しています。")
        self.admin_var = tk.StringVar(value="")
        self.adapter_var = tk.StringVar(value="")
        self.mode_var = tk.StringVar(value=InputMode.LLDPDU.value)
        self.status_var = tk.StringVar(value="準備中です。")

        self._build_widgets()
        self.refresh_npcap_status()
        self.refresh_adapters()
        self.after(100, self._poll_events)

    def _build_widgets(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(3, weight=1)

        top = ttk.LabelFrame(self, text="環境")
        top.grid(row=0, column=0, sticky="ew", padx=12, pady=(12, 6))
        top.columnconfigure(1, weight=1)

        ttk.Label(top, text="Npcap").grid(row=0, column=0, sticky="w", padx=8, pady=6)
        ttk.Label(top, textvariable=self.npcap_var).grid(
            row=0, column=1, sticky="ew", padx=8, pady=6
        )
        ttk.Button(top, text="再確認", command=self.refresh_npcap_status).grid(
            row=0, column=2, padx=4, pady=6
        )
        ttk.Button(top, text="初回設定", command=self.install_npcap).grid(
            row=0, column=3, padx=8, pady=6
        )

        ttk.Label(top, text="権限").grid(row=1, column=0, sticky="w", padx=8, pady=6)
        ttk.Label(top, textvariable=self.admin_var).grid(
            row=1, column=1, sticky="ew", padx=8, pady=6
        )

        adapter_frame = ttk.LabelFrame(self, text="ネットワークアダプター")
        adapter_frame.grid(row=1, column=0, sticky="ew", padx=12, pady=6)
        adapter_frame.columnconfigure(1, weight=1)

        ttk.Label(adapter_frame, text="アダプター").grid(
            row=0, column=0, sticky="w", padx=8, pady=8
        )
        self.adapter_combo = ttk.Combobox(
            adapter_frame,
            textvariable=self.adapter_var,
            state="readonly",
        )
        self.adapter_combo.grid(row=0, column=1, sticky="ew", padx=8, pady=8)
        ttk.Button(adapter_frame, text="更新", command=self.refresh_adapters).grid(
            row=0, column=2, padx=8, pady=8
        )

        send_frame = ttk.LabelFrame(self, text="送信")
        send_frame.grid(row=2, column=0, sticky="nsew", padx=12, pady=6)
        send_frame.columnconfigure(0, weight=1)

        mode_frame = ttk.Frame(send_frame)
        mode_frame.grid(row=0, column=0, sticky="w", padx=8, pady=(8, 4))
        ttk.Radiobutton(
            mode_frame,
            text=InputMode.LLDPDU.value,
            value=InputMode.LLDPDU.value,
            variable=self.mode_var,
        ).grid(row=0, column=0, padx=(0, 16))
        ttk.Radiobutton(
            mode_frame,
            text=InputMode.ETHERNET_FRAME.value,
            value=InputMode.ETHERNET_FRAME.value,
            variable=self.mode_var,
        ).grid(row=0, column=1)

        self.input_text = scrolledtext.ScrolledText(send_frame, height=7, wrap="word")
        self.input_text.grid(row=1, column=0, sticky="nsew", padx=8, pady=4)
        self.input_text.insert("1.0", "02 07 04 00 11 22 33 44 55 04 03 02 00 06 00 00")

        send_buttons = ttk.Frame(send_frame)
        send_buttons.grid(row=2, column=0, sticky="ew", padx=8, pady=8)
        ttk.Button(send_buttons, text="送信", command=self.send_packet).grid(
            row=0, column=0, padx=(0, 8)
        )
        ttk.Button(send_buttons, text="入力をクリア", command=self.clear_input).grid(
            row=0, column=1, padx=(0, 8)
        )
        ttk.Button(send_buttons, text="入力をコピー", command=self.copy_input).grid(
            row=0, column=2, padx=(0, 8)
        )

        receive_frame = ttk.LabelFrame(self, text="受信")
        receive_frame.grid(row=3, column=0, sticky="nsew", padx=12, pady=6)
        receive_frame.columnconfigure(0, weight=1)
        receive_frame.rowconfigure(1, weight=1)

        receive_buttons = ttk.Frame(receive_frame)
        receive_buttons.grid(row=0, column=0, sticky="ew", padx=8, pady=8)
        self.start_button = ttk.Button(
            receive_buttons, text="受信開始", command=self.start_receive
        )
        self.start_button.grid(row=0, column=0, padx=(0, 8))
        self.stop_button = ttk.Button(
            receive_buttons, text="受信停止", command=self.stop_receive, state="disabled"
        )
        self.stop_button.grid(row=0, column=1, padx=(0, 8))
        ttk.Button(
            receive_buttons, text="受信ログをクリア", command=self.clear_receive_log
        ).grid(row=0, column=2, padx=(0, 8))
        ttk.Button(
            receive_buttons, text="受信内容をコピー", command=self.copy_receive_log
        ).grid(row=0, column=3, padx=(0, 8))

        self.receive_text = scrolledtext.ScrolledText(receive_frame, wrap="word")
        self.receive_text.grid(row=1, column=0, sticky="nsew", padx=8, pady=(0, 8))

        status = ttk.Label(self, textvariable=self.status_var, anchor="w")
        status.grid(row=4, column=0, sticky="ew", padx=12, pady=(0, 12))

    def refresh_npcap_status(self) -> None:
        status = detect_npcap_status()
        self.npcap_var.set(status.message)
        self.admin_var.set(
            "管理者権限で実行中です。"
            if is_running_as_admin()
            else "管理者権限ではありません。送受信や初回設定で失敗する場合があります。"
        )

    def install_npcap(self) -> None:
        installer = find_bundled_npcap_installer()
        if installer is None:
            messagebox.showerror(
                "初回設定",
                "同梱された Npcap インストーラーが見つかりません。",
            )
            return
        try:
            launch_npcap_installer(installer)
        except Exception as exc:
            messagebox.showerror("初回設定", f"Npcap インストーラーの起動に失敗しました。\n{exc}")
            return
        messagebox.showinfo(
            "初回設定",
            "Npcap インストーラーを起動しました。完了後に「再確認」を押してください。",
        )

    def refresh_adapters(self) -> None:
        try:
            self.adapters = self.runtime.list_adapters()
        except ScapyRuntimeError as exc:
            self.adapters = []
            self.adapter_combo["values"] = []
            self.status_var.set(str(exc))
            return

        labels = [format_adapter_label(adapter) for adapter in self.adapters]
        self.adapter_combo["values"] = labels
        if labels:
            self.adapter_combo.current(0)
            self.status_var.set("ネットワークアダプターを更新しました。")
        else:
            self.status_var.set("利用可能なネットワークアダプターが見つかりません。")

    def selected_adapter(self) -> AdapterInfo | None:
        index = self.adapter_combo.current()
        if index < 0 or index >= len(self.adapters):
            return None
        return self.adapters[index]

    def send_packet(self) -> None:
        adapter = self.selected_adapter()
        if adapter is None:
            messagebox.showerror("送信", "ネットワークアダプターを選択してください。")
            return

        try:
            data = parse_hex_bytes(self.input_text.get("1.0", "end"))
            packet = build_packet_from_input(self.mode_var.get(), data, adapter.mac)
            self.runtime.send_frame(adapter.name, packet.full_frame)
        except (HexParseError, PacketBuildError, ScapyRuntimeError) as exc:
            messagebox.showerror("送信", str(exc))
            self.status_var.set(str(exc))
            return

        self.status_var.set(f"送信に成功しました。{len(packet.full_frame)} byte")

    def clear_input(self) -> None:
        self.input_text.delete("1.0", "end")

    def copy_input(self) -> None:
        self.clipboard_clear()
        self.clipboard_append(self.input_text.get("1.0", "end").strip())
        self.status_var.set("入力内容をコピーしました。")

    def start_receive(self) -> None:
        adapter = self.selected_adapter()
        if adapter is None:
            messagebox.showerror("受信", "ネットワークアダプターを選択してください。")
            return
        if self.receiver_thread and self.receiver_thread.is_alive():
            return

        self.receiver_stop.clear()
        self.receiver_thread = threading.Thread(
            target=self._receive_loop,
            args=(adapter,),
            daemon=True,
        )
        self.receiver_thread.start()
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.status_var.set("受信を開始しました。")

    def stop_receive(self) -> None:
        self.receiver_stop.set()
        self.start_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        self.status_var.set("受信停止を要求しました。")

    def _receive_loop(self, adapter: AdapterInfo) -> None:
        while not self.receiver_stop.is_set():
            try:
                packets = self.runtime.sniff_once(adapter.name, timeout=1.0)
            except ScapyRuntimeError as exc:
                self.event_queue.put(("error", str(exc)))
                break
            for packet in packets:
                self.event_queue.put(("packet", (adapter.name, packet, datetime.now())))
        self.event_queue.put(("stopped", None))

    def _poll_events(self) -> None:
        while True:
            try:
                kind, payload = self.event_queue.get_nowait()
            except queue.Empty:
                break

            if kind == "packet":
                adapter_name, packet, received_at = payload  # type: ignore[misc]
                self.receive_text.insert(
                    "end",
                    format_received_packet(packet, adapter_name, received_at),
                )
                self.receive_text.see("end")
            elif kind == "error":
                message = str(payload)
                messagebox.showerror("受信", message)
                self.status_var.set(message)
                self.stop_receive()
            elif kind == "stopped":
                self.start_button.configure(state="normal")
                self.stop_button.configure(state="disabled")
                if self.receiver_stop.is_set():
                    self.status_var.set("受信を停止しました。")

        self.after(100, self._poll_events)

    def clear_receive_log(self) -> None:
        self.receive_text.delete("1.0", "end")
        self.status_var.set("受信ログをクリアしました。")

    def copy_receive_log(self) -> None:
        self.clipboard_clear()
        self.clipboard_append(self.receive_text.get("1.0", "end").strip())
        self.status_var.set("受信内容をコピーしました。")

    def destroy(self) -> None:
        self.receiver_stop.set()
        super().destroy()


def main() -> None:
    app = LldpToolApp()
    app.mainloop()
