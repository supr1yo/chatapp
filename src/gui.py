import threading
import tkinter as tk
from src import crypto, network

def launch(conn, shared_key, other_sign):
    win = tk.Tk()
    win.title("Secure Chat")
    win.resizable(False, False)

    # Chat display
    chat_frame = tk.Frame(win)
    chat_frame.pack(padx=8, pady=(8, 4), fill=tk.BOTH, expand=True)

    chat = tk.Text(chat_frame, height=20, width=60, state="disabled",
                   wrap=tk.WORD, relief=tk.FLAT, bg="#f5f5f5")
    scrollbar = tk.Scrollbar(chat_frame, command=chat.yview)
    chat.config(yscrollcommand=scrollbar.set)

    chat.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    # Input row
    input_frame = tk.Frame(win)
    input_frame.pack(padx=8, pady=(0, 8), fill=tk.X)
    input_frame.columnconfigure(0, weight=1)

    box = tk.Entry(input_frame)
    box.grid(row=0, column=0, sticky="ew", ipady=4)

    send_btn = tk.Button(input_frame, text="Send", width=8)
    send_btn.grid(row=0, column=1, padx=(6, 0))


    def _append(line: str):
        chat.config(state="normal")
        chat.insert(tk.END, line + "\n")
        chat.config(state="disabled")
        chat.see(tk.END)

    def send(event=None):
        msg = box.get().strip()
        if not msg:
            return
        enc = crypto.encrypt(msg, shared_key)
        sig = crypto.sign(enc)
        conn.send(len(sig).to_bytes(4, "big") + sig)
        conn.send(len(enc).to_bytes(4, "big") + enc)
        _append("You: " + msg)
        box.delete(0, tk.END)

    def receive():
        while True:
            try:
                sig_len = int.from_bytes(network.recv_exact(conn, 4), "big")
                sig     = network.recv_exact(conn, sig_len)
                dat_len = int.from_bytes(network.recv_exact(conn, 4), "big")
                data    = network.recv_exact(conn, dat_len)

                if crypto.verify(data, sig, other_sign):
                    _append("Friend: " + crypto.decrypt(data, shared_key))
                else:
                    _append("⚠ Tampered message — discarded.")
            except Exception:
                _append("Connection closed.")
                break

    send_btn.config(command=send)
    box.bind("<Return>", send)
    box.focus_set()

    threading.Thread(target=receive, daemon=True).start()
    win.mainloop()