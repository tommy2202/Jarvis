from __future__ import annotations

from tkinter import ttk


class VoiceControls(ttk.Frame):
    def __init__(self, master, *, on_voice_toggle, on_wake_toggle, on_push_to_talk):  # noqa: ANN001
        super().__init__(master, padding=(8, 6))
        self._on_voice_toggle = on_voice_toggle
        self._on_wake_toggle = on_wake_toggle
        self._on_push_to_talk = on_push_to_talk

        self._voice_var = ttk.BooleanVar(value=False)
        self._wake_var = ttk.BooleanVar(value=False)

        self._voice = ttk.Checkbutton(self, text="Voice enabled", variable=self._voice_var, command=self._voice_changed)
        self._wake = ttk.Checkbutton(self, text="Wake word enabled", variable=self._wake_var, command=self._wake_changed)
        self._ptt = ttk.Button(self, text="Push-to-talk", command=self._on_push_to_talk)

        self._status = ttk.Label(self, text="Voice controls use Jarvis core adapters only.")

        self._voice.grid(row=0, column=0, padx=(0, 12), sticky="w")
        self._wake.grid(row=0, column=1, padx=(0, 12), sticky="w")
        self._ptt.grid(row=0, column=2, sticky="e")
        self._status.grid(row=1, column=0, columnspan=3, sticky="w", pady=(4, 0))

        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=1)
        self.columnconfigure(2, weight=0)

    def _voice_changed(self) -> None:
        self._on_voice_toggle(bool(self._voice_var.get()))

    def _wake_changed(self) -> None:
        self._on_wake_toggle(bool(self._wake_var.get()))

    def set_state(self, *, available: bool, voice_enabled: bool, wake_enabled: bool) -> None:
        self._voice_var.set(bool(voice_enabled))
        self._wake_var.set(bool(wake_enabled))
        if not available:
            self._status.configure(text="Voice subsystem unavailable (no adapter configured).")
            self._voice.configure(state="disabled")
            self._wake.configure(state="disabled")
            self._ptt.configure(state="disabled")
        else:
            self._voice.configure(state="normal")
            self._wake.configure(state="normal" if voice_enabled else "disabled")
            self._ptt.configure(state="normal" if voice_enabled else "disabled")
            self._status.configure(text="Push-to-talk captures one utterance via core voice adapter.")

