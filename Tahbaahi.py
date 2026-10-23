#!/usr/bin/env python3
"""
Cipher Tool - encryption & decryption with a desktop GUI (Tkinter).

Ciphers: Atbash, Caesar, Rail Fence, Vernam (letters-only), Vigenere, Playfair.
Run:  python cipher_tool.py
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
def main():
    import tkinter as tk
    from tkinter import ttk

    BG, PANEL, FG = "#1e1f2b", "#2a2c3d", "#e6e8f0"
    MUTED, ACCENT, ACCENT_H = "#9aa0b8", "#6c8cff", "#8aa3ff"
    OK, ERR, WARN = "#5fd49a", "#ff6b7a", "#f5c26b"
    FONT, MONO = ("Segoe UI", 10), ("Consolas", 11)

    root = tk.Tk()
    root.title("Cipher Tool")
    root.configure(bg=BG)
    root.geometry("760x820")
    root.minsize(640, 700)

    style = ttk.Style(root)
    style.theme_use("clam")
    style.configure("TFrame", background=BG)
    style.configure("Card.TFrame", background=PANEL)
    style.configure("TLabel", background=BG, foreground=FG, font=FONT)
    style.configure("Card.TLabel", background=PANEL, foreground=FG, font=FONT)
    style.configure("Title.TLabel", background=BG, foreground=FG,
                    font=("Segoe UI", 20, "bold"))
    style.configure("Sub.TLabel", background=BG, foreground=MUTED, font=FONT)
    style.configure("Step.TLabel", background=PANEL, foreground=ACCENT,
                    font=("Segoe UI", 10, "bold"))
    style.configure("TRadiobutton", background=PANEL, foreground=FG, font=FONT)
    style.map("TRadiobutton", background=[("active", PANEL)])
    style.configure("TCombobox", fieldbackground="#363950", background="#363950",
                    foreground=FG, arrowcolor=FG, padding=6)
    style.map("TCombobox", fieldbackground=[("readonly", "#363950")],
              foreground=[("readonly", FG)])
    style.configure("Run.TButton", background=ACCENT, foreground="white",
                    font=("Segoe UI", 11, "bold"), padding=10, borderwidth=0)
    style.map("Run.TButton", background=[("active", ACCENT_H)])
    style.configure("Ghost.TButton", background="#363950", foreground=FG,
                    font=FONT, padding=8, borderwidth=0)
    style.map("Ghost.TButton", background=[("active", "#444868")])
    root.option_add("*TCombobox*Listbox.background", "#363950")
    root.option_add("*TCombobox*Listbox.foreground", FG)

    outer = ttk.Frame(root, padding=20)
    outer.pack(fill="both", expand=True)

    ttk.Label(outer, text="Cipher Tool", style="Title.TLabel").pack(anchor="w")
    ttk.Label(outer, text="Classical encryption & decryption",
              style="Sub.TLabel").pack(anchor="w", pady=(0, 14))

    def card(title):
        f = ttk.Frame(outer, style="Card.TFrame", padding=14)
        f.pack(fill="x", pady=6)
        ttk.Label(f, text=title, style="Step.TLabel").pack(anchor="w", pady=(0, 6))
        return f

    # Step 1: cipher
    c1 = card("STEP 1  ·  CHOOSE A CIPHER")
    cipher_var = tk.StringVar(value=list(CIPHERS)[0])
    combo = ttk.Combobox(c1, textvariable=cipher_var, values=list(CIPHERS),
                         state="readonly", font=FONT)
    combo.pack(fill="x")
    notice = tk.Label(c1, text="", bg=PANEL, fg=WARN, font=("Segoe UI", 9),
                      wraplength=680, justify="left", anchor="w")
    notice.pack(fill="x", pady=(8, 0))

    # Step 2: mode
    c2 = card("STEP 2  ·  ENCRYPT OR DECRYPT")
    mode_var = tk.StringVar(value="enc")
    row = ttk.Frame(c2, style="Card.TFrame")
    row.pack(anchor="w")
    ttk.Radiobutton(row, text="Encrypt", value="enc", variable=mode_var).pack(
        side="left", padx=(0, 20))
    ttk.Radiobutton(row, text="Decrypt", value="dec", variable=mode_var).pack(
        side="left")

    # Step 3: message
    c3 = card("STEP 3  ·  ENTER YOUR MESSAGE")
    msg_box = tk.Text(c3, height=5, wrap="word", bg="#363950", fg=FG,
                      insertbackground=FG, relief="flat", font=MONO,
                      padx=8, pady=8)
    msg_box.pack(fill="x")

    # Step 4: key
    c4 = card("STEP 4  ·  KEY")
    key_label = ttk.Label(c4, text="", style="Card.TLabel")
    key_label.pack(anchor="w")
    key_var = tk.StringVar()
    key_entry = tk.Entry(c4, textvariable=key_var, bg="#363950", fg=FG,
                         insertbackground=FG, relief="flat", font=MONO,
                         disabledbackground="#2f3144", disabledforeground=MUTED)
    key_entry.pack(fill="x", ipady=6, pady=(4, 0))

    # Buttons
    btns = ttk.Frame(outer)
    btns.pack(fill="x", pady=10)
    run_btn = ttk.Button(btns, text="▶  Run", style="Run.TButton")
    run_btn.pack(side="left", fill="x", expand=True, padx=(0, 8))
    clear_btn = ttk.Button(btns, text="Clear", style="Ghost.TButton")
    clear_btn.pack(side="left")

    # Result
    c5 = card("RESULT")
    status = tk.Label(c5, text="", bg=PANEL, fg=MUTED, font=("Segoe UI", 9),
                      wraplength=680, justify="left", anchor="w")
    status.pack(fill="x")
    out_box = tk.Text(c5, height=5, wrap="word", bg="#14151d", fg=OK,
                      relief="flat", font=MONO, padx=8, pady=8, state="disabled")
    out_box.pack(fill="x", pady=(4, 8))
    copy_btn = ttk.Button(c5, text="Copy result", style="Ghost.TButton")
    copy_btn.pack(anchor="e")

    # Behaviour
    def set_output(text, color=OK):
        out_box.configure(state="normal", fg=color)
        out_box.delete("1.0", "end")
        out_box.insert("1.0", text)
        out_box.configure(state="disabled")

    def on_cipher_change(*_):
        _, label, hint, note = CIPHERS[cipher_var.get()]
        notice.configure(text="ℹ  " + note)
        if label is None:
            key_label.configure(text="This cipher does not use a key")
            key_var.set("")
            key_entry.configure(state="disabled")
        else:
            key_label.configure(text=label + (f"   ({hint})" if hint else ""))
            key_entry.configure(state="normal")

    def run(*_):
        func = CIPHERS[cipher_var.get()][0]
        text = msg_box.get("1.0", "end-1c")
        if not text.strip():
            status.configure(text="Please enter a message.", fg=ERR)
            set_output("")
            return
        try:
            result = func(text, key_var.get().strip(), mode_var.get() == "enc")
        except CipherError as e:
            status.configure(text="⚠  " + str(e), fg=ERR)
            set_output("")
            return
        verb = "Encrypted" if mode_var.get() == "enc" else "Decrypted"
        status.configure(text=f"✔  {verb} with {cipher_var.get()}", fg=OK)
        set_output(result)

    def clear():
        msg_box.delete("1.0", "end")
        key_var.set("")
        status.configure(text="")
        set_output("")

    def copy():
        root.clipboard_clear()
        root.clipboard_append(out_box.get("1.0", "end-1c"))
        status.configure(text="Copied to clipboard.", fg=MUTED)

    combo.bind("<<ComboboxSelected>>", on_cipher_change)
    run_btn.configure(command=run)
    clear_btn.configure(command=clear)
    copy_btn.configure(command=copy)
    key_entry.bind("<Return>", run)
    on_cipher_change()
    root.mainloop()


if __name__ == "__main__":
    main()
