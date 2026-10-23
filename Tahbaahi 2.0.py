#!/usr/bin/env python3
"""
Cipher Tool - encryption & decryption with a desktop GUI (Tkinter).

Ciphers: Atbash, Caesar, Rail Fence, Vernam (letters-only), Vigenere, Playfair.
Run:  python Tahbaahi.py
"""

import string

ALPHA = string.ascii_uppercase


# ----------------------------------------------------------------------------
# Cipher logic (no GUI dependencies, so it can be imported and tested)
# ----------------------------------------------------------------------------
class CipherError(Exception):
    """Raised for invalid input or keys; the message is shown to the user."""


def _shift_char(ch, shift):
    """Shift a letter, preserving case. Non-letters are returned unchanged."""
    if ch.isascii() and ch.isalpha():
        base = ord("A") if ch.isupper() else ord("a")
        return chr((ord(ch) - base + shift) % 26 + base)
    return ch


def atbash(text, key, encrypt):
    out = []
    for ch in text:
        if ch.isascii() and ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            out.append(chr(base + 25 - (ord(ch) - base)))
        else:
            out.append(ch)
    return "".join(out)  # self-inverse: same for enc/dec


def caesar(text, key, encrypt):
    try:
        shift = int(key)
    except ValueError:
        raise CipherError("Caesar key must be a whole number (e.g. 3).")
    if not encrypt:
        shift = -shift
    return "".join(_shift_char(c, shift) for c in text)


def _rail_order(n, rails):
    pattern, rail, step = [], 0, 1
    for _ in range(n):
        pattern.append(rail)
        if rails > 1:
            if rail == 0:
                step = 1
            elif rail == rails - 1:
                step = -1
            rail += step
    return sorted(range(n), key=lambda i: pattern[i])  # stable sort


def railfence(text, key, encrypt):
    try:
        rails = int(key)
    except ValueError:
        raise CipherError("Rail Fence key must be a whole number of rails (e.g. 3).")
    if rails < 2:
        raise CipherError("Rail Fence needs at least 2 rails.")
    order = _rail_order(len(text), rails)
    if encrypt:
        return "".join(text[i] for i in order)
    result = [""] * len(text)
    for j, i in enumerate(order):
        result[i] = text[j]
    return "".join(result)


def vernam(text, key, encrypt):
    msg = "".join(c for c in text.upper() if c in ALPHA)
    k = key.upper().replace(" ", "")
    if not msg:
        raise CipherError("Vernam needs a message containing letters A-Z.")
    if not k.isalpha() or not k.isascii():
        raise CipherError("Vernam key must contain letters A-Z only.")
    if len(k) != len(msg):
        raise CipherError(
            f"Vernam key must be the same length as the message "
            f"({len(msg)} letters after removing spaces/punctuation; "
            f"your key has {len(k)})."
        )
    sign = 1 if encrypt else -1
    return "".join(
        ALPHA[(ALPHA.index(m) + sign * ALPHA.index(c)) % 26] for m, c in zip(msg, k)
    )


def vigenere(text, key, encrypt):
    k = [c for c in key.upper() if c in ALPHA]
    if not k:
        raise CipherError("Vigenere key must contain at least one letter A-Z.")
    out, i = [], 0
    for ch in text:
        if ch.isascii() and ch.isalpha():
            shift = ALPHA.index(k[i % len(k)])
            out.append(_shift_char(ch, shift if encrypt else -shift))
            i += 1
        else:
            out.append(ch)
    return "".join(out)


def _playfair_square(key):
    seen = []
    for c in (key.upper().replace("J", "I") + ALPHA.replace("J", "")):
        if c in ALPHA and c not in seen:
            seen.append(c)
    return seen  # 25 letters


def playfair(text, key, encrypt):
    if not any(c in ALPHA for c in key.upper()):
        raise CipherError("Playfair key must contain at least one letter A-Z.")
    square = _playfair_square(key)
    pos = {c: divmod(i, 5) for i, c in enumerate(square)}
    t = [c for c in text.upper().replace("J", "I") if c in ALPHA]
    if not t:
        raise CipherError("Playfair needs a message containing letters A-Z.")

    if encrypt:
        pairs, i = [], 0
        while i < len(t):
            a = t[i]
            b = t[i + 1] if i + 1 < len(t) else "X"
            if a == b:
                b, i = "X", i + 1
            else:
                i += 2
            pairs.append((a, b))
    else:
        if len(t) % 2:
            raise CipherError("Playfair ciphertext must have an even number of letters.")
        pairs = [(t[i], t[i + 1]) for i in range(0, len(t), 2)]

    d = 1 if encrypt else -1
    out = []
    for a, b in pairs:
        (r1, c1), (r2, c2) = pos[a], pos[b]
        if r1 == r2:
            c1, c2 = (c1 + d) % 5, (c2 + d) % 5
        elif c1 == c2:
            r1, r2 = (r1 + d) % 5, (r2 + d) % 5
        else:
            c1, c2 = c2, c1
        out.append(square[r1 * 5 + c1] + square[r2 * 5 + c2])
    return "".join(out)


# name -> (function, key_label or None, key_hint, notice)
CIPHERS = {
    "Atbash Cipher": (
        atbash, None, "",
        "No key needed. Mirrors the alphabet (A<->Z, B<->Y). Case and spaces are "
        "kept; digits and symbols pass through unchanged. Encrypting and "
        "decrypting are the same operation.",
    ),
    "Caesar Cipher": (
        caesar, "Shift (whole number)", "e.g. 3",
        "Shifts each letter by the key. Case and spaces are kept; digits and "
        "symbols pass through unchanged.",
    ),
    "Rail Fence Cipher": (
        railfence, "Number of rails (2 or more)", "e.g. 3",
        "Works on every character including spaces, and keeps case. Spaces are "
        "scrambled too, so decryption needs the exact ciphertext (including any "
        "trailing spaces).",
    ),
    "Vernam Cipher": (
        vernam, "Key (letters A-Z, same length as message)", "",
        "LETTERS ONLY. Spaces, digits and punctuation are removed and the output "
        "is UPPERCASE with no spaces. The key must be exactly as long as the "
        "message (letters only). Use a truly random key, used once, for real "
        "one-time-pad security.",
    ),
    "Vigenere Cipher": (
        vigenere, "Keyword (letters A-Z)", "e.g. LEMON",
        "Case and spaces are kept; digits and symbols pass through unchanged. "
        "Spaces do not consume key letters.",
    ),
    "Playfair Cipher": (
        playfair, "Keyword (letters A-Z)", "e.g. MONARCHY",
        "LETTERS ONLY. Spaces, digits and punctuation are removed; output is "
        "UPPERCASE with no spaces. J is merged into I. Repeated letters in a "
        "pair and odd lengths get an 'X' filler, so decrypted text may contain "
        "extra X's and need manual tidying.",
    ),
}


# ----------------------------------------------------------------------------
# GUI
# ----------------------------------------------------------------------------
THEMES = {
    "dark": dict(
        bg="#172226", surface="#1E2C31", field="#121B1E", border="#2E4148",
        text="#E4E7DF", muted="#8FA3A3", accent="#D4A84B", accent_hover="#E2BC66",
        on_accent="#1A1405", ok="#9CD3A8", err="#F08A7A", grid="#2A3B41",
    ),
    "light": dict(
        bg="#E3E9E8", surface="#F4F7F6", field="#FFFFFF", border="#C3CFCD",
        text="#1C2A2E", muted="#566A6C", accent="#8C6A1C", accent_hover="#A57E25",
        on_accent="#FFFFFF", ok="#2F7A4F", err="#B23A2C", grid="#DCE3E2",
    ),
}

SHORTCUTS = "      ".join(
    s.replace(" ", "\u00a0") for s in (
        "Ctrl+Enter run", "Ctrl+M switch encrypt/decrypt",
        "Ctrl+R use result as input", "Ctrl+Shift+C copy result", "Ctrl+L clear",
        "Ctrl+1 to 6 choose cipher", "Ctrl+Shift+T switch theme",
    )
)


def _pick_font(available, *names):
    for n in names:
        if n in available:
            return n
    return names[-1]


def main():
    import tkinter as tk
    from tkinter import ttk, font as tkfont

    root = tk.Tk()
    root.title("Cipher Tool")
    root.geometry("1100x760")
    root.minsize(660, 640)

    families = set(tkfont.families())
    UI = _pick_font(families, "Bahnschrift", "Segoe UI", "Helvetica Neue",
                    "DejaVu Sans", "TkDefaultFont")
    MONO = _pick_font(families, "Cascadia Mono", "Consolas", "Menlo",
                      "DejaVu Sans Mono", "Courier New")
    F_BODY, F_SMALL = (UI, 10), (UI, 9)
    F_LABEL, F_TITLE = (UI, 10, "bold"), (UI, 18, "bold")
    F_MONO, F_MONO_S = (MONO, 12), (MONO, 10)

    state = {"theme": "dark", "wide": None, "job": None, "status": "muted"}
    style = ttk.Style(root)
    style.theme_use("clam")

    # ---------------- layout ----------------
    outer = ttk.Frame(root, padding=(20, 16, 20, 12))
    outer.pack(fill="both", expand=True)
    outer.columnconfigure(0, weight=1)
    outer.rowconfigure(3, weight=1)

    # Header
    header = ttk.Frame(outer)
    header.grid(row=0, column=0, sticky="ew")
    header.columnconfigure(0, weight=1)
    ttk.Label(header, text="Cipher Tool", style="Title.TLabel").grid(
        row=0, column=0, sticky="w")
    ttk.Label(header, text="Encrypt and decrypt with six classical ciphers",
              style="Muted.TLabel").grid(row=1, column=0, sticky="w")
    theme_btn = ttk.Button(header, style="Ghost.TButton", takefocus=True)
    theme_btn.grid(row=0, column=1, rowspan=2, sticky="e")

    # Controls card
    controls = ttk.Frame(outer, style="Surface.TFrame", padding=14)
    controls.grid(row=1, column=0, sticky="ew", pady=(14, 8))
    controls.columnconfigure(2, weight=1)

    ttk.Label(controls, text="Cipher", style="Field.TLabel").grid(
        row=0, column=0, sticky="w")
    cipher_var = tk.StringVar(value=list(CIPHERS)[0])
    combo = ttk.Combobox(controls, textvariable=cipher_var, values=list(CIPHERS),
                         state="readonly", font=F_BODY, width=20)
    combo.grid(row=1, column=0, sticky="w", padx=(0, 16))

    ttk.Label(controls, text="Mode", style="Field.TLabel").grid(
        row=0, column=1, sticky="w")
    mode_var = tk.StringVar(value="enc")
    seg = ttk.Frame(controls, style="Surface.TFrame")
    seg.grid(row=1, column=1, sticky="w", padx=(0, 16))
    ttk.Radiobutton(seg, text="Encrypt", value="enc", variable=mode_var,
                    style="Seg.Toolbutton").pack(side="left")
    ttk.Radiobutton(seg, text="Decrypt", value="dec", variable=mode_var,
                    style="Seg.Toolbutton").pack(side="left")

    key_label = ttk.Label(controls, text="Key", style="Field.TLabel")
    key_var = tk.StringVar()
    key_entry = ttk.Entry(controls, textvariable=key_var, font=F_MONO)
    notice = ttk.Label(controls, style="Note.TLabel", justify="left")

    # Key preview
    prev_card = ttk.Frame(outer, style="Surface.TFrame", padding=(14, 10, 14, 10))
    prev_card.grid(row=2, column=0, sticky="ew", pady=(0, 8))
    prev_card.columnconfigure(0, weight=1)
    ttk.Label(prev_card, text="Key preview", style="Field.TLabel").grid(
        row=0, column=0, sticky="w")
    canvas = tk.Canvas(prev_card, height=118, highlightthickness=0, bd=0)
    canvas.grid(row=1, column=0, sticky="ew", pady=(6, 0))

    # Input / output panes
    io = ttk.Frame(outer)
    io.grid(row=3, column=0, sticky="nsew")

    def text_pane(title):
        f = ttk.Frame(io, style="Surface.TFrame", padding=12)
        f.columnconfigure(0, weight=1)
        f.rowconfigure(1, weight=1)
        ttk.Label(f, text=title, style="Field.TLabel").grid(row=0, column=0, sticky="w")
        count = ttk.Label(f, text="", style="Count.TLabel")
        count.grid(row=0, column=1, sticky="e")
        box = tk.Text(f, wrap="word", relief="flat", font=F_MONO, padx=10, pady=8,
                      height=6, width=30, undo=True, highlightthickness=1, bd=0)
        box.grid(row=1, column=0, columnspan=2, sticky="nsew", pady=(6, 0))
        return f, box, count

    in_pane, msg_box, in_count = text_pane("Message")
    out_pane, out_box, out_count = text_pane("Result")
    out_box.configure(state="disabled", undo=False)

    # Action bar
    actions = ttk.Frame(outer)
    actions.grid(row=4, column=0, sticky="ew", pady=(10, 0))
    status = ttk.Label(actions, text="", style="Status.TLabel")
    live_var = tk.BooleanVar(value=True)
    btn_row = ttk.Frame(actions)
    live_chk = ttk.Checkbutton(btn_row, text="Live preview", variable=live_var)
    live_chk.pack(side="left", padx=(0, 12))
    run_btn = ttk.Button(btn_row, text="Run", style="Accent.TButton")
    swap_btn = ttk.Button(btn_row, text="Use result as input", style="Ghost.TButton")
    copy_btn = ttk.Button(btn_row, text="Copy result", style="Ghost.TButton")
    clear_btn = ttk.Button(btn_row, text="Clear", style="Ghost.TButton")
    for b in (run_btn, swap_btn, copy_btn, clear_btn):
        b.pack(side="left", padx=(0, 6))
    hint = ttk.Label(outer, text=SHORTCUTS, style="Hint.TLabel", justify="left")
    hint.grid(row=5, column=0, sticky="ew", pady=(8, 0))

    # ---------------- theming ----------------
    def apply_theme():
        t = THEMES[state["theme"]]
        root.configure(bg=t["bg"])
        style.configure(".", background=t["bg"], foreground=t["text"], font=F_BODY,
                        bordercolor=t["border"], focuscolor=t["accent"],
                        lightcolor=t["surface"], darkcolor=t["surface"],
                        troughcolor=t["field"])
        style.configure("TFrame", background=t["bg"])
        style.configure("Surface.TFrame", background=t["surface"])
        style.configure("TLabel", background=t["bg"], foreground=t["text"])
        style.configure("Title.TLabel", font=F_TITLE)
        style.configure("Muted.TLabel", foreground=t["muted"])
        style.configure("Hint.TLabel", foreground=t["muted"], font=F_SMALL)
        style.configure("Status.TLabel", foreground=t[state["status"]])
        style.configure("Field.TLabel", background=t["surface"], foreground=t["text"],
                        font=F_LABEL)
        style.configure("Count.TLabel", background=t["surface"], foreground=t["muted"],
                        font=F_SMALL)
        style.configure("Note.TLabel", background=t["surface"], foreground=t["muted"],
                        font=F_SMALL)
        style.configure("TCombobox", fieldbackground=t["field"], background=t["field"],
                        foreground=t["text"], arrowcolor=t["text"], padding=5,
                        bordercolor=t["border"], lightcolor=t["field"],
                        darkcolor=t["field"], selectbackground=t["field"],
                        selectforeground=t["text"])
        style.map("TCombobox",
                  fieldbackground=[("readonly", t["field"])],
                  foreground=[("readonly", t["text"])],
                  bordercolor=[("focus", t["accent"])],
                  selectbackground=[("readonly", t["field"])],
                  selectforeground=[("readonly", t["text"])])
        style.configure("TEntry", fieldbackground=t["field"], foreground=t["text"],
                        insertcolor=t["text"], bordercolor=t["border"],
                        lightcolor=t["field"], darkcolor=t["field"], padding=5)
        style.map("TEntry",
                  fieldbackground=[("disabled", t["surface"])],
                  foreground=[("disabled", t["muted"])],
                  bordercolor=[("focus", t["accent"])])
        style.configure("Accent.TButton", background=t["accent"],
                        foreground=t["on_accent"], font=F_LABEL, padding=(16, 7),
                        borderwidth=0, lightcolor=t["accent"], darkcolor=t["accent"])
        style.map("Accent.TButton",
                  background=[("disabled", t["border"]), ("active", t["accent_hover"])],
                  foreground=[("disabled", t["muted"])])
        style.configure("Ghost.TButton", background=t["surface"], foreground=t["text"],
                        padding=(12, 7), borderwidth=1, bordercolor=t["border"],
                        lightcolor=t["surface"], darkcolor=t["surface"])
        style.map("Ghost.TButton", background=[("active", t["grid"])],
                  bordercolor=[("focus", t["accent"])])
        style.configure("Seg.Toolbutton", background=t["field"], foreground=t["muted"],
                        padding=(14, 6), borderwidth=1, bordercolor=t["border"],
                        lightcolor=t["field"], darkcolor=t["field"], font=F_BODY)
        style.map("Seg.Toolbutton",
                  background=[("selected", t["accent"]), ("active", t["grid"])],
                  foreground=[("selected", t["on_accent"]), ("active", t["text"])],
                  bordercolor=[("focus", t["accent"])])
        style.configure("TCheckbutton", background=t["bg"], foreground=t["text"],
                        indicatorbackground=t["field"], indicatorforeground=t["accent"])
        style.map("TCheckbutton", background=[("active", t["bg"])],
                  indicatorbackground=[("selected", t["field"])])
        for box in (msg_box, out_box):
            box.configure(bg=t["field"], fg=t["text"], insertbackground=t["text"],
                          selectbackground=t["accent"], selectforeground=t["on_accent"],
                          highlightbackground=t["border"], highlightcolor=t["accent"],
                          inactiveselectbackground=t["border"])
        canvas.configure(bg=t["surface"])
        try:  # restyle the combobox dropdown list
            pop = combo.tk.eval(f"ttk::combobox::PopdownWindow {combo}")
            combo.tk.call(f"{pop}.f.l", "configure", "-background", t["field"],
                          "-foreground", t["text"], "-selectbackground", t["accent"],
                          "-selectforeground", t["on_accent"])
        except tk.TclError:
            pass
        theme_btn.configure(text="Light theme" if state["theme"] == "dark"
                            else "Dark theme")
        draw_preview()

    def toggle_theme(*_):
        state["theme"] = "light" if state["theme"] == "dark" else "dark"
        apply_theme()
        return "break"

    # ---------------- responsive panes ----------------
    def layout(wide):
        if state["wide"] == wide:
            return
        state["wide"] = wide
        # Controls: key field beside the mode switch, or on its own row.
        key_label.grid_forget()
        key_entry.grid_forget()
        if wide:
            controls.columnconfigure(2, weight=1)
            key_label.grid(row=0, column=2, sticky="w")
            key_entry.grid(row=1, column=2, sticky="ew")
        else:
            controls.columnconfigure(2, weight=0)
            controls.columnconfigure(1, weight=1)
            key_label.grid(row=2, column=0, columnspan=3, sticky="w", pady=(10, 0))
            key_entry.grid(row=3, column=0, columnspan=3, sticky="ew")
        if wide:
            controls.columnconfigure(1, weight=0)
        notice.grid(row=4, column=0, columnspan=3, sticky="ew", pady=(10, 0))
        # Action bar: status beside the buttons, or above them.
        status.grid_forget()
        btn_row.grid_forget()
        if wide:
            actions.columnconfigure(0, weight=1)
            status.grid(row=0, column=0, sticky="w")
            btn_row.grid(row=0, column=1, sticky="e")
        else:
            status.grid(row=0, column=0, sticky="w")
            btn_row.grid(row=1, column=0, sticky="w", pady=(8, 0))
        # Message and result panes.
        in_pane.grid_forget()
        out_pane.grid_forget()
        for i in range(2):
            io.columnconfigure(i, weight=0, uniform="")
            io.rowconfigure(i, weight=0, uniform="")
        if wide:
            in_pane.grid(row=0, column=0, sticky="nsew", padx=(0, 4))
            out_pane.grid(row=0, column=1, sticky="nsew", padx=(4, 0))
            io.columnconfigure(0, weight=1, uniform="io")
            io.columnconfigure(1, weight=1, uniform="io")
            io.rowconfigure(0, weight=1)
        else:
            in_pane.grid(row=0, column=0, sticky="nsew", pady=(0, 4))
            out_pane.grid(row=1, column=0, sticky="nsew", pady=(4, 0))
            io.columnconfigure(0, weight=1)
            io.rowconfigure(0, weight=1, uniform="io")
            io.rowconfigure(1, weight=1, uniform="io")

    def on_resize(event):
        if event.widget is root:
            layout(event.width >= 860)
            wrap = max(300, event.width - 80)
            notice.configure(wraplength=wrap)
            hint.configure(wraplength=wrap)
            status.configure(wraplength=wrap if event.width < 860 else wrap - 560)
            schedule_preview()

    # ---------------- key preview ----------------
    preview_job = {"id": None}

    def schedule_preview():
        if preview_job["id"]:
            root.after_cancel(preview_job["id"])
        preview_job["id"] = root.after(30, draw_preview)

    def draw_preview():
        preview_job["id"] = None
        t = THEMES[state["theme"]]
        c = canvas
        c.delete("all")
        w = max(c.winfo_width(), 300)
        h = int(c.cget("height"))
        name = cipher_var.get()
        key = key_var.get().strip()
        message = msg_box.get("1.0", "end-1c")

        def caption(text, y=h - 10):
            c.create_text(0, y, text=text, anchor="w", fill=t["muted"], font=F_SMALL)

        def alpha_rows(bottom, note):
            label_w = 56
            cell = min(30, (w - label_w) / 26)
            for row, (label, letters, colour) in enumerate(
                    (("Plain", ALPHA, t["muted"]), ("Cipher", bottom, t["accent"]))):
                y = 18 + row * 34
                c.create_text(0, y, text=label, anchor="w", fill=t["muted"], font=F_SMALL)
                for i, ch in enumerate(letters):
                    x = label_w + i * cell + cell / 2
                    if row == 1:
                        c.create_rectangle(x - cell / 2 + 1, y - 13, x + cell / 2 - 1,
                                           y + 13, fill=t["field"], outline="")
                    c.create_text(x, y, text=ch, fill=colour, font=F_MONO_S)
            for i in range(26):
                x = label_w + i * cell + cell / 2
                c.create_line(x, 32, x, 38, fill=t["border"])
            caption(note, 84)

        if name == "Atbash Cipher":
            alpha_rows(ALPHA[::-1], "The alphabet is mirrored, so A becomes Z and Z becomes A.")
        elif name == "Caesar Cipher":
            try:
                shift = int(key)
            except ValueError:
                caption("Enter a whole number to see the shifted alphabet.", h / 2)
                return
            s = shift % 26
            direction = "Decrypting moves each letter back" if mode_var.get() == "dec" \
                else "Encrypting moves each letter forward"
            alpha_rows(ALPHA[s:] + ALPHA[:s],
                       f"Shift {shift}. {direction} {abs(shift)} places.")
        elif name == "Vigenere Cipher":
            letters = [ch for ch in key.upper() if ch in ALPHA]
            if not letters:
                caption("Enter a keyword to see the shift each key letter applies.", h / 2)
                return
            chip_w, gap = 46, 6
            per_row = max(1, int((w + gap) // (chip_w + gap)))
            shown = letters[: per_row * 2]
            for i, ch in enumerate(shown):
                r, col = divmod(i, per_row)
                x, y = col * (chip_w + gap), 6 + r * 44
                c.create_rectangle(x, y, x + chip_w, y + 38, fill=t["field"],
                                   outline=t["border"])
                c.create_text(x + chip_w / 2, y + 13, text=ch, fill=t["accent"],
                              font=(MONO, 12, "bold"))
                c.create_text(x + chip_w / 2, y + 29, text=f"+{ALPHA.index(ch)}",
                              fill=t["muted"], font=F_SMALL)
            more = len(letters) - len(shown)
            caption("Each message letter uses the next key letter's shift; spaces and "
                    "symbols don't use up key letters." + (f"  ({more} more not shown)"
                                                           if more else ""))
        elif name == "Playfair Cipher":
            if not any(ch in ALPHA for ch in key.upper()):
                caption("Enter a keyword to see the 5 by 5 key square.", h / 2)
                return
            square = _playfair_square(key)
            key_letters = set(key.upper().replace("J", "I"))
            cell = 20
            for i, ch in enumerate(square):
                r, col = divmod(i, 5)
                x, y = col * (cell + 2), r * (cell + 2) + 2
                in_key = ch in key_letters
                c.create_rectangle(x, y, x + cell, y + cell,
                                   fill=t["accent"] if in_key else t["field"], outline="")
                c.create_text(x + cell / 2, y + cell / 2, text=ch,
                              fill=t["on_accent"] if in_key else t["text"], font=F_MONO_S)
            tx = 5 * (cell + 2) + 18
            for j, line in enumerate((
                    "Highlighted letters come from your keyword and fill the square first.",
                    "J is merged into I.",
                    ("Same row: take the letter to the right. Same column: the letter below."
                     if mode_var.get() == "enc" else
                     "Same row: take the letter to the left. Same column: the letter above."),
                    "Otherwise: swap columns to the opposite corners of the rectangle.")):
                c.create_text(tx, 12 + j * 22, text=line, anchor="w",
                              fill=t["muted"], font=F_SMALL)
        elif name == "Rail Fence Cipher":
            try:
                rails = int(key)
            except ValueError:
                caption("Enter the number of rails to see how the message zigzags.", h / 2)
                return
            if rails < 2:
                caption("Use at least 2 rails.", h / 2)
                return
            if not message:
                caption("Type a message to see how it zigzags across the rails.", h / 2)
                return
            shown_rails = min(rails, 5)
            cell_w = 18
            row_h = min(20, (h - 26) / shown_rails)
            cols = int(w // cell_w)
            rail, step = 0, 1
            for i, ch in enumerate(message[:cols]):
                if rail < shown_rails:
                    c.create_text(i * cell_w + cell_w / 2, 10 + rail * row_h,
                                  text="␣" if ch == " " else ("↵" if ch == "\n" else ch),
                                  fill=t["accent"], font=F_MONO_S)
                if rail == 0:
                    step = 1
                elif rail == rails - 1:
                    step = -1
                rail += step
            note = "Reading each rail left to right gives the ciphertext."
            if rails > shown_rails:
                note += f" Showing the top {shown_rails} of {rails} rails."
            if len(message) > cols:
                note += f" Showing the first {cols} characters."
            caption(note)
        elif name == "Vernam Cipher":
            m = sum(1 for ch in message.upper() if ch in ALPHA)
            k = sum(1 for ch in key.upper() if ch in ALPHA)
            bar_w = min(w, 520)
            for row, (label, n) in enumerate((("Message letters", m), ("Key letters", k))):
                y = 14 + row * 30
                c.create_text(0, y, text=f"{label}: {n}", anchor="w", fill=t["text"],
                              font=F_SMALL)
                c.create_rectangle(140, y - 6, 140 + bar_w - 140, y + 6,
                                   fill=t["field"], outline="")
                top = max(m, k, 1)
                c.create_rectangle(140, y - 6, 140 + (bar_w - 140) * n / top, y + 6,
                                   fill=t["accent"] if row else t["muted"], outline="")
            if m == 0:
                note, colour = "Type a message to see how many key letters you need.", t["muted"]
            elif k == m:
                note, colour = "Key length matches the message.", t["ok"]
            elif k < m:
                note, colour = f"Add {m - k} more key letter{'s' if m - k != 1 else ''}.", t["err"]
            else:
                note, colour = f"Remove {k - m} key letter{'s' if k - m != 1 else ''}.", t["err"]
            c.create_text(0, h - 10, text=note, anchor="w", fill=colour, font=F_SMALL)

    # ---------------- behaviour ----------------
    def set_output(text):
        out_box.configure(state="normal")
        out_box.delete("1.0", "end")
        out_box.insert("1.0", text)
        out_box.configure(state="disabled")
        out_count.configure(text=f"{len(text)} characters" if text else "")

    def set_status(text, kind="muted"):
        state["status"] = kind
        t = THEMES[state["theme"]]
        style.configure("Status.TLabel", foreground=t[kind])
        status.configure(text=text)

    def update_counts():
        text = msg_box.get("1.0", "end-1c")
        letters = sum(1 for ch in text if ch.isascii() and ch.isalpha())
        in_count.configure(text=f"{len(text)} characters, {letters} letters" if text else "")

    def run(*_, quiet=False):
        state["job"] = None
        name = cipher_var.get()
        func, label = CIPHERS[name][0], CIPHERS[name][1]
        text = msg_box.get("1.0", "end-1c")
        key = key_var.get().strip()
        if not text.strip():
            set_output("")
            set_status("Type or paste a message to begin.")
            return "break"
        if label is not None and not key:
            set_output("")
            set_status("Enter a key to see the result.")
            return "break"
        try:
            result = func(text, key, mode_var.get() == "enc")
        except CipherError as e:
            set_output("")
            set_status(str(e), "err")
            return "break"
        verb = "Encrypted" if mode_var.get() == "enc" else "Decrypted"
        set_output(result)
        set_status(f"{verb} with {name}.", "ok")
        return "break"

    def changed(*_):
        update_counts()
        schedule_preview()
        if live_var.get():
            if state["job"]:
                root.after_cancel(state["job"])
            state["job"] = root.after(120, run)
        else:
            set_status("Press Run or Ctrl+Enter to update the result.")

    def on_cipher_change(*_):
        _, label, hint, note = CIPHERS[cipher_var.get()]
        notice.configure(text=note)
        if label is None:
            key_label.configure(text="Key (not used by this cipher)")
            key_entry.configure(state="disabled")
        else:
            key_label.configure(text=label + (f", {hint}" if hint else ""))
            key_entry.configure(state="normal")
        changed()

    def on_live_toggle(*_):
        if live_var.get():
            run_btn.pack_forget()
            run()
        else:
            run_btn.pack(side="left", padx=(0, 6), before=swap_btn)
            set_status("Live preview is off. Press Run or Ctrl+Enter.")

    def on_text_modified(_):
        if msg_box.edit_modified():
            msg_box.edit_modified(False)
            changed()

    def toggle_mode(*_):
        mode_var.set("dec" if mode_var.get() == "enc" else "enc")
        return "break"

    def swap(*_):
        result = out_box.get("1.0", "end-1c")
        if not result:
            set_status("Run a cipher first, then use its result as input.")
            return "break"
        msg_box.delete("1.0", "end")
        msg_box.insert("1.0", result)
        toggle_mode()
        new_mode = "Decrypt" if mode_var.get() == "dec" else "Encrypt"
        if not live_var.get():
            set_status(f"Result moved to the message box. Mode switched to {new_mode}.")
        msg_box.focus_set()
        return "break"

    def copy(*_):
        result = out_box.get("1.0", "end-1c")
        if not result:
            set_status("Nothing to copy yet.")
            return "break"
        root.clipboard_clear()
        root.clipboard_append(result)
        set_status("Result copied to clipboard.", "ok")
        return "break"

    def clear(*_):
        msg_box.delete("1.0", "end")
        key_var.set("")
        set_output("")
        msg_box.focus_set()
        return "break"

    def choose(i):
        def handler(*_):
            names = list(CIPHERS)
            if i < len(names):
                cipher_var.set(names[i])
                on_cipher_change()
            return "break"
        return handler

    # ---------------- wiring ----------------
    combo.bind("<<ComboboxSelected>>", on_cipher_change)
    mode_var.trace_add("write", changed)
    key_var.trace_add("write", changed)
    live_var.trace_add("write", on_live_toggle)
    msg_box.bind("<<Modified>>", on_text_modified)
    theme_btn.configure(command=toggle_theme)
    run_btn.configure(command=run)
    swap_btn.configure(command=swap)
    copy_btn.configure(command=copy)
    clear_btn.configure(command=clear)
    key_entry.bind("<Return>", run)
    root.bind("<Configure>", on_resize)

    shortcuts = {
        "<Control-Return>": run,
        "<Control-KP_Enter>": run,
        "<Control-m>": toggle_mode,
        "<Control-r>": swap,
        "<Control-C>": copy,          # Ctrl+Shift+C
        "<Control-l>": clear,
        "<Control-T>": toggle_theme,  # Ctrl+Shift+T
    }
    for i in range(6):
        shortcuts[f"<Control-Key-{i + 1}>"] = choose(i)
    for seq, fn in shortcuts.items():
        # Bind on the text widgets first so their built-in bindings don't fire.
        for w in (msg_box, out_box, key_entry):
            w.bind(seq, fn)
        root.bind_all(seq, fn)

    apply_theme()
    layout(True)
    on_cipher_change()
    on_live_toggle()
    msg_box.focus_set()
    root.mainloop()


if __name__ == "__main__":
    main()
