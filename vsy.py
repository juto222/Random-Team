import tkinter as tk
from tkinter import messagebox

def ajouter_qlq():
    ajt = add.get()
    if ajt.strip(): 
        zone_texte.insert(tk.END, ajt + "\n")  
        add.delete(0, tk.END)  
        messagebox.showinfo("Succès", "Ajouté avec succès !")
    else:
        messagebox.showerror("Erreur", "Remplissez le champ !")

tkt = tk.Tk()
tkt.title("Random Team")
tkt.geometry("900x700")

frame = tk.Frame(tkt, pady=50)
frame.pack()

add = tk.Entry(frame, bg="#339999")
add.pack(side="left", padx=20)

ajouter = tk.Button(frame, text="Ajouter", command=ajouter_qlq, bg="#339933")
ajouter.pack(side="left")

radio_bouton = tk.Frame(tkt)
radio_bouton.pack()

nb = tk.Radiobutton(radio_bouton, text="Nombre de personnes par groupe")
nb.pack(side="left")
nb_prsn = tk.Radiobutton(radio_bouton, text="Nombre de groupe")
nb_prsn.pack(side="left", padx=20)

zone_texte = tk.Text(tkt, height=20, width=80, state="disabled")  
zone_texte.pack(pady=20)

tkt.mainloop()
