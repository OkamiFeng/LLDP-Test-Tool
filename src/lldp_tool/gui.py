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
from .periodic import CounterByteRule, PeriodicConfigError, PeriodicSendConfig
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


def format_periodic_send_status(
    send_count: int,
    counter_value: int | None,
    sent_bytes: int,
) -> str:
    counter_text = (
        f"反映byte値: 0x{counter_value:02X}、" if counter_value is not None else ""
    )
    return f"周期送信 {send_count}回目に成功しました。{counter_text}送信byte数: {sent_bytes}"


class LldpToolApp(tk.Tk):
    def __init__(self, runtime: ScapyLldpRuntime | None = None):
        super().__init__()
        self.title(APP_TITLE)
        self.minsize(980, 720)

        self.runtime = runtime or ScapyLldpRuntime()
        self.adapters: list[AdapterInfo] = []
        self.receiver_stop = threading.Event()
        self.receiver_thread: threading.Thread | None = None
        self.periodic_stop = threading.Event()
        self.periodic_thread: threading.Thread | None = None
        self.periodic_failed = False
        self.event_queue: queue.Queue[tuple[str, object]] = queue.Queue()

        self.npcap_var = tk.StringVar(value="Npcap 状態を確認しています。")
        self.admin_var = tk.StringVar(value="")
        self.adapter_var = tk.StringVar(value="")
        self.mode_var = tk.StringVar(value=InputMode.LLDPDU.value)
        self.periodic_interval_var = tk.StringVar(value="1")
        self.counter_enabled_var = tk.BooleanVar(value=False)
        self.counter_position_var = tk.StringVar(value="3")
        self.counter_start_var = tk.StringVar(value="0x01")
        self.status_var = tk.StringVar(value="準備中です。")
        self.send_lock_widgets: list[tk.Widget] = []

        self._build_widgets()
        self.after(0, self.refresh_npcap_status)
        self.after(50, self.refresh_adapters)
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
        self.adapter_update_button = ttk.Button(
            adapter_frame, text="更新", command=self.refresh_adapters
        )
        self.adapter_update_button.grid(row=0, column=2, padx=8, pady=8)

        send_frame = ttk.LabelFrame(self, text="送信")
        send_frame.grid(row=2, column=0, sticky="nsew", padx=12, pady=6)
        send_frame.columnconfigure(0, weight=1)

        mode_frame = ttk.Frame(send_frame)
        mode_frame.grid(row=0, column=0, sticky="w", padx=8, pady=(8, 4))
        self.lldpdu_radio = ttk.Radiobutton(
            mode_frame,
            text=InputMode.LLDPDU.value,
            value=InputMode.LLDPDU.value,
            variable=self.mode_var,
        )
        self.lldpdu_radio.grid(row=0, column=0, padx=(0, 16))
        self.ethernet_radio = ttk.Radiobutton(
            mode_frame,
            text=InputMode.ETHERNET_FRAME.value,
            value=InputMode.ETHERNET_FRAME.value,
            variable=self.mode_var,
        )
        self.ethernet_radio.grid(row=0, column=1)

        self.input_text = scrolledtext.ScrolledText(send_frame, height=7, wrap="word")
        self.input_text.grid(row=1, column=0, sticky="nsew", padx=8, pady=4)
        self.input_text.insert("1.0", "02 07 04 00 11 22 33 44 55 04 03 02 00 06 00 00")

        send_buttons = ttk.Frame(send_frame)
        send_buttons.grid(row=2, column=0, sticky="ew", padx=8, pady=8)
        self.send_button = ttk.Button(
            send_buttons, text="送信", command=self.send_packet
        )
        self.send_button.grid(row=0, column=0, padx=(0, 8))
        self.clear_input_button = ttk.Button(
            send_buttons, text="入力をクリア", command=self.clear_input
        )
        self.clear_input_button.grid(row=0, column=1, padx=(0, 8))
        self.copy_input_button = ttk.Button(
            send_buttons, text="入力をコピー", command=self.copy_input
        )
        self.copy_input_button.grid(row=0, column=2, padx=(0, 8))

        periodic_frame = ttk.LabelFrame(send_frame, text="周期送信")
        periodic_frame.grid(row=3, column=0, sticky="ew", padx=8, pady=(0, 8))
        periodic_frame.columnconfigure(7, weight=1)

        ttk.Label(periodic_frame, text="周期(秒)").grid(
            row=0, column=0, sticky="w", padx=(8, 4), pady=8
        )
        self.periodic_interval_spin = ttk.Spinbox(
            periodic_frame,
            from_=1,
            to=3600,
            width=8,
            textvariable=self.periodic_interval_var,
        )
        self.periodic_interval_spin.grid(row=0, column=1, sticky="w", padx=(0, 12), pady=8)

        self.counter_check = ttk.Checkbutton(
            periodic_frame,
            text="送信回数をbyteへ反映",
            variable=self.counter_enabled_var,
            command=self._update_counter_controls_state,
        )
        self.counter_check.grid(row=0, column=2, sticky="w", padx=(0, 12), pady=8)

        ttk.Label(periodic_frame, text="対象byte位置").grid(
            row=0, column=3, sticky="w", padx=(0, 4), pady=8
        )
        self.counter_position_entry = ttk.Entry(
            periodic_frame,
            width=8,
            textvariable=self.counter_position_var,
        )
        self.counter_position_entry.grid(row=0, column=4, sticky="w", padx=(0, 12), pady=8)

        ttk.Label(periodic_frame, text="開始値").grid(
            row=0, column=5, sticky="w", padx=(0, 4), pady=8
        )
        self.counter_start_entry = ttk.Entry(
            periodic_frame,
            width=8,
            textvariable=self.counter_start_var,
        )
        self.counter_start_entry.grid(row=0, column=6, sticky="w", padx=(0, 12), pady=8)

        self.periodic_start_button = ttk.Button(
            periodic_frame, text="周期送信開始", command=self.start_periodic_send
        )
        self.periodic_start_button.grid(row=0, column=8, sticky="e", padx=(0, 8), pady=8)
        self.periodic_stop_button = ttk.Button(
            periodic_frame,
            text="周期送信停止",
            command=self.stop_periodic_send,
            state="disabled",
        )
        self.periodic_stop_button.grid(row=0, column=9, sticky="e", padx=(0, 8), pady=8)

        self.send_lock_widgets = [
            self.adapter_combo,
            self.adapter_update_button,
            self.lldpdu_radio,
            self.ethernet_radio,
            self.input_text,
            self.send_button,
            self.clear_input_button,
            self.copy_input_button,
            self.periodic_interval_spin,
            self.counter_check,
            self.counter_position_entry,
            self.counter_start_entry,
            self.periodic_start_button,
        ]
        self._update_counter_controls_state()

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

    def start_periodic_send(self) -> None:
        if self.periodic_thread and self.periodic_thread.is_alive():
            return

        try:
            config = self._build_periodic_config()
        except (HexParseError, PeriodicConfigError, PacketBuildError) as exc:
            messagebox.showerror("周期送信", str(exc))
            self.status_var.set(str(exc))
            return

        self.periodic_stop.clear()
        self.periodic_failed = False
        self.periodic_thread = threading.Thread(
            target=self._periodic_send_loop,
            args=(config,),
            daemon=True,
        )
        self._set_periodic_controls_running(True)
        self.periodic_thread.start()
        self.status_var.set("周期送信を開始しました。")

    def stop_periodic_send(self) -> None:
        self.periodic_stop.set()
        self.periodic_stop_button.configure(state="disabled")
        self.status_var.set("周期送信停止を要求しました。")

    def _build_periodic_config(self) -> PeriodicSendConfig:
        adapter = self.selected_adapter()
        if adapter is None:
            raise PeriodicConfigError("ネットワークアダプターを選択してください。")

        data = parse_hex_bytes(self.input_text.get("1.0", "end"))
        counter_rule = None
        if self.counter_enabled_var.get():
            counter_rule = CounterByteRule(
                position=self._parse_counter_position(),
                start_value=self._parse_counter_start_value(),
            )

        return PeriodicSendConfig(
            interval_seconds=self._parse_periodic_interval(),
            mode=self.mode_var.get(),
            input_data=data,
            source_mac=adapter.mac,
            adapter_name=adapter.name,
            counter_enabled=self.counter_enabled_var.get(),
            counter_rule=counter_rule,
        )

    def _parse_periodic_interval(self) -> int:
        try:
            interval = int(self.periodic_interval_var.get().strip())
        except ValueError as exc:
            raise PeriodicConfigError("周期は1から3600秒で指定してください。") from exc
        if interval < 1 or interval > 3600:
            raise PeriodicConfigError("周期は1から3600秒で指定してください。")
        return interval

    def _parse_counter_position(self) -> int:
        try:
            position = int(self.counter_position_var.get().strip())
        except ValueError as exc:
            raise PeriodicConfigError("対象byte位置は1以上で指定してください。") from exc
        if position < 1:
            raise PeriodicConfigError("対象byte位置は1以上で指定してください。")
        return position

    def _parse_counter_start_value(self) -> int:
        text = self.counter_start_var.get().strip()
        if text.lower().startswith("0x"):
            text = text[2:]
        try:
            value = int(text, 16)
        except ValueError as exc:
            raise PeriodicConfigError("開始値は0x00から0xFFで指定してください。") from exc
        if value < 0 or value > 0xFF:
            raise PeriodicConfigError("開始値は0x00から0xFFで指定してください。")
        return value

    def _periodic_send_loop(self, config: PeriodicSendConfig) -> None:
        send_count = 0
        try:
            while not self.periodic_stop.is_set():
                send_count += 1
                try:
                    result = config.packet_for_send(send_count)
                    self.runtime.send_frame(config.adapter_name, result.packet.full_frame)
                except (PeriodicConfigError, PacketBuildError, ScapyRuntimeError) as exc:
                    self.event_queue.put(("periodic_error", str(exc)))
                    self.periodic_stop.set()
                    break
                except Exception as exc:
                    self.event_queue.put(
                        ("periodic_error", f"周期送信中にエラーが発生しました。\n{exc}")
                    )
                    self.periodic_stop.set()
                    break

                self.event_queue.put(
                    (
                        "periodic_sent",
                        (send_count, result.counter_value, len(result.packet.full_frame)),
                    )
                )
                if self.periodic_stop.wait(config.interval_seconds):
                    break
        finally:
            self.event_queue.put(("periodic_stopped", None))

    def _set_periodic_controls_running(self, running: bool) -> None:
        for widget in self.send_lock_widgets:
            if widget is self.adapter_combo:
                widget.configure(state="disabled" if running else "readonly")
            else:
                widget.configure(state="disabled" if running else "normal")

        self.periodic_stop_button.configure(state="normal" if running else "disabled")
        if not running:
            self._update_counter_controls_state()

    def _update_counter_controls_state(self) -> None:
        if self.periodic_thread and self.periodic_thread.is_alive():
            state = "disabled"
        else:
            state = "normal" if self.counter_enabled_var.get() else "disabled"
        self.counter_position_entry.configure(state=state)
        self.counter_start_entry.configure(state=state)

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
            elif kind == "periodic_sent":
                send_count, counter_value, sent_bytes = payload  # type: ignore[misc]
                self.status_var.set(
                    format_periodic_send_status(send_count, counter_value, sent_bytes)
                )
            elif kind == "periodic_error":
                message = str(payload)
                self.periodic_failed = True
                self.periodic_stop.set()
                self._set_periodic_controls_running(False)
                messagebox.showerror("周期送信", message)
                self.status_var.set(message)
            elif kind == "periodic_stopped":
                self.periodic_thread = None
                self._set_periodic_controls_running(False)
                if self.periodic_stop.is_set() and not self.periodic_failed:
                    self.status_var.set("周期送信を停止しました。")

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
        self.periodic_stop.set()
        super().destroy()


def main() -> None:
    app = LldpToolApp()
    app.mainloop()
