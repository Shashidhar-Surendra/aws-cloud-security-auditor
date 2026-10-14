#!/usr/bin/env python3
"""
AWS Cloud Security Auditor — Graphical Launcher
================================================
A Tkinter-based GUI wrapper around the existing audit engine.

No audit logic lives here. This file only handles:
  - User input (region, profile, output directory)
  - Running the audit in a background thread (keeps the window responsive)
  - Displaying live log output and a progress indicator
  - Translating technical errors into plain-English messages
  - Opening the finished HTML report in the default browser

Usage:
    python launcher_gui.py          # double-click on Windows/Mac/Linux
"""

from __future__ import annotations

import os
import sys
import threading
import webbrowser
from pathlib import Path

# ---------------------------------------------------------------------------
# Tkinter import — guide the user if it is missing (rare but possible)
# ---------------------------------------------------------------------------
try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, scrolledtext
except ImportError:
    print(
        "ERROR: Tkinter is not available.\n"
        "On Ubuntu/Debian: sudo apt-get install python3-tk\n"
        "On Fedora:        sudo dnf install python3-tkinter\n"
        "On macOS:         reinstall Python from python.org (includes Tk)\n"
        "On Windows:       reinstall Python and tick 'tcl/tk' during setup.",
        file=sys.stderr,
    )
    sys.exit(1)

# ---------------------------------------------------------------------------
# AWS error → plain-English translation table
# ---------------------------------------------------------------------------
_FRIENDLY_ERRORS: list[tuple[str, str]] = [
    (
        "NoCredentialsError",
        "AWS credentials not found.\n\n"
        "Configure an AWS CLI profile first:\n"
        "  1. Open a terminal / command prompt\n"
        "  2. Run:  aws configure\n"
        "  3. Enter your Access Key ID and Secret Access Key\n"
        "  4. Re-run the audit",
    ),
    (
        "ProfileNotFound",
        "The selected AWS profile was not found.\n\n"
        "Check the profile name or leave the field blank to use the default profile.",
    ),
    (
        "AccessDenied",
        "AWS denied access to one or more API calls.\n\n"
        "Make sure the IAM user / role has the AWSSecurityAuditorReadOnly policy attached.\n"
        "See docs/required-iam-policy.json for the exact permissions needed.",
    ),
    (
        "InvalidClientTokenId",
        "The AWS Access Key ID is not valid.\n\n"
        "Reconfigure your AWS CLI profile:\n"
        "  aws configure",
    ),
    (
        "SignatureDoesNotMatch",
        "The AWS Secret Access Key is incorrect.\n\n"
        "Reconfigure your AWS CLI profile:\n"
        "  aws configure",
    ),
    (
        "EndpointResolutionError",
        "Could not reach AWS.\n\n"
        "Check your internet connection and try again.",
    ),
]


def _friendly_error(exc: Exception) -> str:
    exc_str = str(exc)
    exc_type = type(exc).__name__
    for keyword, message in _FRIENDLY_ERRORS:
        if keyword in exc_type or keyword in exc_str:
            return message
    # Fallback: show the exception but with a helpful note
    return (
        f"An unexpected error occurred:\n\n{exc_type}: {exc_str}\n\n"
        "Check the detailed log below for more information."
    )


# ---------------------------------------------------------------------------
# AWS region list (common regions + custom entry)
# ---------------------------------------------------------------------------
COMMON_REGIONS = [
    "eu-central-1",
    "eu-west-1",
    "eu-west-2",
    "eu-west-3",
    "eu-north-1",
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
    "ap-southeast-1",
    "ap-southeast-2",
    "ap-northeast-1",
    "ap-south-1",
    "ca-central-1",
    "sa-east-1",
    "Custom region...",
]


# ---------------------------------------------------------------------------
# Main application window
# ---------------------------------------------------------------------------

class AuditorApp(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("AWS Cloud Security Auditor  v5.0.0")
        self.resizable(True, True)
        self.minsize(640, 580)
        self._report_path: Path | None = None
        self._audit_thread: threading.Thread | None = None

        self._build_ui()
        self._center_window()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self):
        # ---- top padding ----
        pad = {"padx": 16, "pady": 6}

        # ---- header ----
        header = tk.Frame(self, bg="#1a2a3a")
        header.pack(fill="x")
        tk.Label(
            header,
            text="☁  AWS Cloud Security Auditor",
            bg="#1a2a3a", fg="white",
            font=("Helvetica", 16, "bold"),
            pady=14,
        ).pack(side="left", padx=20)
        tk.Label(
            header,
            text="v5.0.0  |  read-only",
            bg="#1a2a3a", fg="#8ab4d4",
            font=("Helvetica", 10),
        ).pack(side="right", padx=20)

        # ---- config frame ----
        cfg = ttk.LabelFrame(self, text="Audit Configuration", padding=12)
        cfg.pack(fill="x", **pad)
        cfg.columnconfigure(1, weight=1)

        # Region
        ttk.Label(cfg, text="AWS Region:").grid(row=0, column=0, sticky="w", pady=4)
        self._region_var = tk.StringVar(value="eu-central-1")
        self._region_combo = ttk.Combobox(
            cfg, textvariable=self._region_var,
            values=COMMON_REGIONS, width=28, state="normal",
        )
        self._region_combo.grid(row=0, column=1, sticky="ew", padx=(8, 0))
        self._region_combo.bind("<<ComboboxSelected>>", self._on_region_select)

        # Custom region entry (hidden by default)
        self._custom_region_var = tk.StringVar()
        self._custom_region_entry = ttk.Entry(cfg, textvariable=self._custom_region_var, width=28)
        # shown only when "Custom region..." is selected

        # Profile
        ttk.Label(cfg, text="AWS Profile:").grid(row=2, column=0, sticky="w", pady=4)
        self._profile_var = tk.StringVar(value="default")
        ttk.Entry(cfg, textvariable=self._profile_var, width=28).grid(
            row=2, column=1, sticky="ew", padx=(8, 0)
        )
        ttk.Label(cfg, text="Leave blank or 'default' to use the default AWS CLI profile.",
                  foreground="grey").grid(row=3, column=1, sticky="w", padx=(8, 0))

        # Output directory
        ttk.Label(cfg, text="Output Folder:").grid(row=4, column=0, sticky="w", pady=4)
        self._output_var = tk.StringVar(value=str(Path.home() / "aws_audit_reports"))
        out_frame = ttk.Frame(cfg)
        out_frame.grid(row=4, column=1, sticky="ew", padx=(8, 0))
        out_frame.columnconfigure(0, weight=1)
        ttk.Entry(out_frame, textvariable=self._output_var).grid(row=0, column=0, sticky="ew")
        ttk.Button(out_frame, text="Browse…", command=self._browse_output).grid(
            row=0, column=1, padx=(6, 0)
        )

        # ---- progress bar ----
        self._progress = ttk.Progressbar(self, mode="indeterminate", length=300)
        self._progress.pack(fill="x", padx=16, pady=(6, 0))

        # ---- status label ----
        self._status_var = tk.StringVar(value="Ready.")
        self._status_label = ttk.Label(self, textvariable=self._status_var, foreground="#2a6496")
        self._status_label.pack(anchor="w", padx=18, pady=(2, 0))

        # ---- log box ----
        log_frame = ttk.LabelFrame(self, text="Audit Log", padding=6)
        log_frame.pack(fill="both", expand=True, **pad)
        self._log = scrolledtext.ScrolledText(
            log_frame, height=12, state="disabled",
            font=("Courier", 9), bg="#0d1117", fg="#c9d1d9",
            insertbackground="white",
        )
        self._log.pack(fill="both", expand=True)

        # ---- buttons ----
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill="x", padx=16, pady=10)

        self._run_btn = ttk.Button(
            btn_frame, text="▶  Run Audit", command=self._start_audit,
            style="Accent.TButton",
        )
        self._run_btn.pack(side="left")

        self._open_btn = ttk.Button(
            btn_frame, text="📄  Open Report", command=self._open_report, state="disabled"
        )
        self._open_btn.pack(side="left", padx=(10, 0))

        ttk.Button(btn_frame, text="Clear Log", command=self._clear_log).pack(side="right")

        # disclaimer
        ttk.Label(
            self,
            text="⚠  Read-only tool. No changes are made to your AWS account.",
            foreground="grey", font=("Helvetica", 9),
        ).pack(pady=(0, 8))

    def _center_window(self):
        self.update_idletasks()
        w, h = 700, 620
        x = (self.winfo_screenwidth() - w) // 2
        y = (self.winfo_screenheight() - h) // 2
        self.geometry(f"{w}x{h}+{x}+{y}")

    # ------------------------------------------------------------------
    # Callbacks
    # ------------------------------------------------------------------

    def _on_region_select(self, _event=None):
        if self._region_var.get() == "Custom region...":
            self._custom_region_entry.grid(row=1, column=1, sticky="ew", padx=(8, 0), pady=(0, 4))
            self._custom_region_entry.focus_set()
        else:
            self._custom_region_entry.grid_forget()

    def _browse_output(self):
        chosen = filedialog.askdirectory(title="Select output folder for reports")
        if chosen:
            self._output_var.set(chosen)

    def _clear_log(self):
        self._log.configure(state="normal")
        self._log.delete("1.0", "end")
        self._log.configure(state="disabled")

    # ------------------------------------------------------------------
    # Audit execution
    # ------------------------------------------------------------------

    def _start_audit(self):
        # Resolve region
        region = self._region_var.get().strip()
        if region == "Custom region...":
            region = self._custom_region_var.get().strip()
        if not region:
            messagebox.showwarning("Missing region", "Please enter an AWS region.")
            return

        profile = self._profile_var.get().strip() or None
        output_dir = self._output_var.get().strip() or str(Path.home() / "aws_audit_reports")

        # Reset UI state
        self._report_path = None
        self._open_btn.configure(state="disabled")
        self._run_btn.configure(state="disabled")
        self._status_var.set("Running audit…")
        self._progress.start(12)
        self._log_write(f"Starting audit — region: {region}  profile: {profile or 'default'}\n")
        self._log_write("─" * 60 + "\n")

        # Run in background thread — keeps the window responsive
        self._audit_thread = threading.Thread(
            target=self._run_audit_thread,
            args=(region, profile, output_dir),
            daemon=True,
        )
        self._audit_thread.start()

    def _run_audit_thread(self, region: str, profile: str | None, output_dir: str):
        """Run the shared application runner in a background thread."""
        try:
            from auditor.runner import run_audit

            self._ui_log("Establishing AWS session…\n")
            result = run_audit(
                region=region,
                profile=profile or "default",
                output_dir=output_dir,
            )

            summary = result["summary"]
            scores = summary.get("scores", {})
            checks = summary.get("checks", {})
            counts = checks.get("status_counts", {})

            self._ui_log(f"Account ID : {result['account_id']}\n")
            self._ui_log(f"Region     : {result['region']}\n")
            self._ui_log("─" * 60 + "\n")
            self._ui_log("AUDIT COMPLETE\n")
            self._ui_log(f"Duration  : {result['duration_seconds']:.2f}s\n")
            self._ui_log(f"Security  : {scores.get('security', 0):.0f}/100\n")
            self._ui_log(f"GDPR      : {scores.get('gdpr', 0):.0f}/100\n")
            self._ui_log(f"NIS2      : {scores.get('nis2', 0):.0f}/100\n")
            self._ui_log(
                f"Results   : "
                f"{counts.get('PASS', 0)} PASS  "
                f"{counts.get('FAIL', 0)} FAIL  "
                f"{counts.get('WARN', 0)} WARN\n"
            )
            coverage = summary.get("coverage", {})
            if coverage:
                self._ui_log(
                    f"Coverage  : {coverage.get('coverage_percent', 0):.1f}% "
                    f"({coverage.get('assessment_confidence', 'UNKNOWN')})\n"
                )
            self._ui_log("─" * 60 + "\n")
            self._ui_log(f"HTML report : {result['html_report']}\n")
            self._ui_log(f"JSON report : {result['json_report']}\n")

            self.after(0, self._on_audit_success, Path(result["html_report"]))

        except Exception as exc:
            friendly = _friendly_error(exc)
            self.after(0, self._on_audit_error, friendly, exc)

    # ------------------------------------------------------------------
    # UI update helpers (called from main thread via after())
    # ------------------------------------------------------------------

    def _on_audit_success(self, html_path: Path):
        self._report_path = html_path
        self._progress.stop()
        self._status_var.set("✔  Audit completed successfully.")
        self._status_label.configure(foreground="#2e7d32")
        self._run_btn.configure(state="normal")
        self._open_btn.configure(state="normal")   # only enabled on success

    def _on_audit_error(self, friendly_msg: str, exc: Exception):
        self._progress.stop()
        self._status_var.set("✘  Audit failed — see details below.")
        self._status_label.configure(foreground="#c62828")
        self._run_btn.configure(state="normal")
        self._open_btn.configure(state="disabled")   # no report to open
        self._ui_log(f"\nERROR:\n{friendly_msg}\n")
        self._ui_log(f"\n[Technical detail: {type(exc).__name__}: {exc}]\n")
        messagebox.showerror("Audit Failed", friendly_msg)

    def _ui_log(self, text: str):
        """Thread-safe log append — schedules the write on the main thread."""
        self.after(0, self._log_write, text)

    def _log_write(self, text: str):
        self._log.configure(state="normal")
        self._log.insert("end", text)
        self._log.see("end")
        self._log.configure(state="disabled")

    def _open_report(self):
        if self._report_path and self._report_path.exists():
            webbrowser.open(self._report_path.as_uri())
        else:
            messagebox.showwarning("Report not found", "The report file could not be located.")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Make sure we can import the auditor package from this file's directory
    sys.path.insert(0, str(Path(__file__).parent))
    app = AuditorApp()
    app.mainloop()
