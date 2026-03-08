#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import socket
import re
import hashlib
import subprocess
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime


ROUGE   = "\033[91m"
VERT    = "\033[92m"
JAUNE   = "\033[93m"
BLEU    = "\033[94m"
CYAN    = "\033[96m"
GRAS    = "\033[1m"
DIM     = "\033[2m"
R       = "\033[0m"


def clear():
    os.system("clear")

def banner():
    clear()
    print(f"""
{CYAN}{GRAS}
  ███╗   ███╗██╗██╗     ███████╗
  ████╗ ████║██║██║     ██╔════╝
  ██╔████╔██║██║██║     ███████╗
  ██║╚██╔╝██║██║██║     ╚════██║
  ██║ ╚═╝ ██║██║███████╗███████║
  ╚═╝     ╚═╝╚═╝╚══════╝╚══════╝
{R}
  {DIM}par Mils  —  github.com/Mils-root{R}
  {JAUNE}⚠  Usage légal uniquement{R}
""")

def sep():
    print(f"  {DIM}{'─' * 50}{R}")

def i(m):   print(f"  {BLEU}[*]{R} {m}")
def ok(m):  print(f"  {VERT}[+]{R} {m}")
def err(m): print(f"  {ROUGE}[-]{R} {m}")
def warn(m):print(f"  {JAUNE}[!]{R} {m}")


def get(url, timeout=8):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8", errors="ignore")
    except:
        return None


def export(nom, contenu):
    ts = datetime.now().strftime("%d-%m-%Y_%H%M%S")
    f = f"mils_{nom}_{ts}.txt"
    try:
        with open(f, "w", encoding="utf-8") as fd:
            fd.write(f"Mils-root — github.com/Mils-root\n")
            fd.write(f"Module : {nom}  |  {ts}\n")
            fd.write("─" * 45 + "\n\n")
            fd.write(contenu)
        ok(f"Sauvegardé → {CYAN}{f}{R}")
    except Exception as e:
        err(f"Erreur export : {e}")


def ask_save(nom, lignes):
    if not lignes:
        return
    r = input(f"\n  {JAUNE}Sauvegarder ?{R} (o/N) : ").strip().lower()
    if r == "o":
        export(nom, "\n".join(lignes))


# ─── Géolocalisation IP ───────────────────────────────────────────────────────

def geoip():
    sep()
    print(f"  {GRAS}GÉOLOCALISATION IP{R}")
    sep()
    cible = input("\n  IP cible (vide = la mienne) : ").strip()

    url = "https://ipapi.co/json/" if not cible else f"https://ipapi.co/{cible}/json/"
    i("Récupération en cours...")
    brut = get(url)
    if not brut:
        err("Connexion échouée.")
        return

    try:
        d = json.loads(brut)
        print()
        res = []
        champs = [
            ("IP",             d.get("ip")),
            ("Ville",          d.get("city")),
            ("Région",         d.get("region")),
            ("Pays",           d.get("country_name")),
            ("Continent",      d.get("continent_code")),
            ("Latitude",       d.get("latitude")),
            ("Longitude",      d.get("longitude")),
            ("Fournisseur",    d.get("org")),
            ("ASN",            d.get("asn")),
            ("Fuseau",         d.get("timezone")),
            ("Indicatif",      d.get("country_calling_code")),
        ]
        for label, val in champs:
            if val:
                print(f"  {CYAN}{label:<16}{R}: {val}")
                res.append(f"{label}: {val}")
        ask_save("geoip", res)
    except:
        err("Impossible de lire la réponse.")


# ─── DNS & WHOIS ──────────────────────────────────────────────────────────────

def dns_whois():
    sep()
    print(f"  {GRAS}DNS & WHOIS{R}")
    sep()
    domaine = input("\n  Domaine : ").strip()
    if not domaine:
        err("Domaine vide.")
        return

    print()
    res = []

    try:
        ip = socket.gethostbyname(domaine)
        ok(f"A         : {VERT}{ip}{R}")
        res.append(f"A: {ip}")
    except:
        err("Enregistrement A introuvable.")

    try:
        ptr = socket.gethostbyaddr(socket.gethostbyname(domaine))[0]
        ok(f"PTR       : {ptr}")
        res.append(f"PTR: {ptr}")
    except:
        pass

    for t in ["MX", "NS", "TXT"]:
        try:
            out = subprocess.check_output(
                ["dig", "+short", t, domaine],
                stderr=subprocess.DEVNULL, timeout=5
            ).decode().strip()
            for l in out.splitlines():
                if l:
                    ok(f"{t:<9} : {l}")
                    res.append(f"{t}: {l}")
        except:
            pass

    i("WHOIS...")
    brut = get(f"https://api.whois.vu/?q={domaine}")
    if brut:
        try:
            d = json.loads(brut)
            txt = str(d.get("whois", ""))
            mots = ["registrar", "created", "expir", "name server", "registrant"]
            for l in txt[:900].splitlines():
                if any(m in l.lower() for m in mots):
                    print(f"  {DIM}  {l}{R}")
                    res.append(l)
        except:
            pass

    ask_save("dns_whois", res)


# ─── Scanner de ports ─────────────────────────────────────────────────────────

def scan_ports():
    sep()
    print(f"  {GRAS}SCANNER DE PORTS{R}")
    sep()
    cible = input("\n  Hôte ou IP : ").strip()
    if not cible:
        err("Cible vide.")
        return

    print(f"\n  {CYAN}[1]{R} Ports connus   {CYAN}[2]{R} Plage manuelle")
    choix = input("  → ").strip()

    if choix == "2":
        try:
            debut, fin = map(int, input("  Plage (ex: 1-1024) : ").split("-"))
            ports = list(range(debut, fin + 1))
        except:
            err("Format invalide.")
            return
    else:
        ports = [21,22,23,25,53,80,110,143,443,445,
                 3306,3389,5432,6379,8080,8443,8888,27017]

    try:
        ip = socket.gethostbyname(cible)
    except:
        err("Résolution échouée.")
        return

    i(f"Scan de {ip} — {len(ports)} port(s)...\n")
    ouverts = []

    for p in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.4)
            if s.connect_ex((ip, p)) == 0:
                svc = {21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",
                       80:"HTTP",110:"POP3",143:"IMAP",443:"HTTPS",445:"SMB",
                       3306:"MySQL",3389:"RDP",5432:"PostgreSQL",6379:"Redis",
                       8080:"HTTP-alt",8443:"HTTPS-alt",8888:"HTTP-dev",
                       27017:"MongoDB"}.get(p, "?")
                ok(f"Port {VERT}{p:<6}{R}  ouvert  {DIM}({svc}){R}")
                ouverts.append(f"Port {p} ouvert ({svc})")
            s.close()
        except:
            pass

    print()
    if not ouverts:
        warn("Aucun port ouvert.")
    else:
        ok(f"{len(ouverts)} port(s) ouvert(s).")
        ask_save("scan_ports", [f"Cible: {ip}"] + ouverts)


# ─── Recherche de pseudo ──────────────────────────────────────────────────────

def pseudo():
    sep()
    print(f"  {GRAS}RECHERCHE DE PSEUDO{R}")
    sep()
    p = input("\n  Pseudo : ").strip()
    if not p:
        err("Pseudo vide.")
        return

    sites = {
        "GitHub":      f"https://github.com/{p}",
        "Twitter/X":   f"https://twitter.com/{p}",
        "Instagram":   f"https://www.instagram.com/{p}/",
        "TikTok":      f"https://www.tiktok.com/@{p}",
        "Reddit":      f"https://www.reddit.com/user/{p}",
        "Pinterest":   f"https://www.pinterest.com/{p}/",
        "Twitch":      f"https://www.twitch.tv/{p}",
        "YouTube":     f"https://www.youtube.com/@{p}",
        "Pastebin":    f"https://pastebin.com/u/{p}",
        "GitLab":      f"https://gitlab.com/{p}",
        "Keybase":     f"https://keybase.io/{p}",
        "Dev.to":      f"https://dev.to/{p}",
        "Medium":      f"https://medium.com/@{p}",
        "Linktree":    f"https://linktr.ee/{p}",
        "Replit":      f"https://replit.com/@{p}",
        "Mastodon":    f"https://mastodon.social/@{p}",
        "HackerNews":  f"https://news.ycombinator.com/user?id={p}",
    }

    i(f"Vérification sur {len(sites)} plateformes...\n")
    trouves = []

    for nom, url in sites.items():
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=5) as r:
                if r.getcode() == 200:
                    ok(f"{nom:<14} {VERT}trouvé{R}  {DIM}{url}{R}")
                    trouves.append(f"{nom}: {url}")
        except urllib.error.HTTPError as e:
            c = e.code
            couleur = ROUGE if c == 404 else DIM
            print(f"  {couleur}  {nom:<14} {c}{R}")
        except:
            print(f"  {DIM}  {nom:<14} timeout{R}")

    print(f"\n  {VERT}{len(trouves)}{R}/{len(sites)} profils trouvés.")
    ask_save("pseudo", trouves)


# ─── OSINT Email ──────────────────────────────────────────────────────────────

def email_osint():
    sep()
    print(f"  {GRAS}OSINT E-MAIL{R}")
    sep()
    mail = input("\n  E-mail : ").strip()
    if not re.match(r"[^@]+@[^@]+\.[^@]+", mail):
        err("Format invalide.")
        return

    dom = mail.split("@")[1]
    res = [f"Email: {mail}", f"Domaine: {dom}"]
    print()

    i(f"Enregistrements MX de {dom}...")
    try:
        out = subprocess.check_output(
            ["dig", "+short", "MX", dom],
            stderr=subprocess.DEVNULL, timeout=5
        ).decode().strip()
        for l in out.splitlines():
            if l:
                ok(f"MX : {l}")
                res.append(f"MX: {l}")
        if not out:
            warn("Aucun MX.")
    except:
        try:
            ip = socket.gethostbyname(dom)
            ok(f"Domaine résolu : {ip}")
        except:
            err("Domaine inconnu.")

    md5 = hashlib.md5(mail.lower().strip().encode()).hexdigest()
    i("Gravatar...")
    try:
        urllib.request.urlopen(
            f"https://www.gravatar.com/avatar/{md5}?d=404", timeout=5
        )
        ok(f"Avatar trouvé → https://gravatar.com/{md5}")
        res.append(f"Gravatar: https://gravatar.com/{md5}")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            warn("Pas de Gravatar.")
    except:
        pass

    hibp = f"https://haveibeenpwned.com/account/{urllib.parse.quote(mail)}"
    i(f"HaveIBeenPwned → {DIM}{hibp}{R}")
    res.append(f"HIBP: {hibp}")

    ask_save("email", res)


# ─── Dorks Google ─────────────────────────────────────────────────────────────

def dorks():
    sep()
    print(f"  {GRAS}GÉNÉRATEUR DE DORKS{R}")
    sep()
    cible = input("\n  Cible (domaine ou nom) : ").strip()
    if not cible:
        err("Vide.")
        return

    liste = [
        f"site:{cible}",
        f"site:{cible} filetype:pdf",
        f"site:{cible} filetype:xls OR filetype:xlsx",
        f"site:{cible} filetype:sql",
        f"site:{cible} filetype:env OR filetype:log OR filetype:bak",
        f"site:{cible} inurl:admin",
        f"site:{cible} inurl:login",
        f"site:{cible} inurl:config",
        f"site:{cible} intext:password",
        f'site:{cible} intext:"index of"',
        f'"{cible}" email',
        f'"{cible}" telephone',
        f'"{cible}" site:linkedin.com',
        f'"{cible}" site:pastebin.com',
        f"cache:{cible}",
        f"related:{cible}",
    ]

    print(f"\n  {CYAN}→ {cible}{R}\n")
    lignes = []
    for n, d in enumerate(liste, 1):
        url = f"https://www.google.com/search?q={urllib.parse.quote(d)}"
        print(f"  {DIM}{n:>2}.{R} {d}")
        lignes.append(f"{d}\n   {url}")

    ask_save("dorks", lignes)


# ─── Sous-domaines ────────────────────────────────────────────────────────────

def subdomains():
    sep()
    print(f"  {GRAS}SOUS-DOMAINES{R}")
    sep()
    dom = input("\n  Domaine : ").strip()
    if not dom:
        err("Vide.")
        return

    wl = [
        "www","mail","ftp","admin","api","dev","staging","test","vpn",
        "smtp","pop","imap","ns1","ns2","cdn","static","assets","blog",
        "shop","app","mobile","m","secure","login","auth","remote",
        "support","status","monitor","dashboard","panel","backend","db",
        "sql","mysql","phpmyadmin","gitlab","git","jenkins","jira",
        "confluence","rh","intranet","corp","webmail","owa","exchange",
    ]

    i(f"Test de {len(wl)} sous-domaines...\n")
    trouves = []

    for sub in wl:
        fqdn = f"{sub}.{dom}"
        try:
            ip = socket.gethostbyname(fqdn)
            ok(f"{fqdn:<36} {VERT}{ip}{R}")
            trouves.append(f"{fqdn} → {ip}")
        except:
            sys.stdout.write(f"\r  {DIM}→ {fqdn:<36}{R}")
            sys.stdout.flush()

    print(f"\n\n  {VERT}{len(trouves)}{R} sous-domaine(s) actif(s).")
    ask_save("subdomains", [f"Domaine: {dom}"] + trouves)


# ─── Reverse IP ───────────────────────────────────────────────────────────────

def reverse_ip():
    sep()
    print(f"  {GRAS}REVERSE IP{R}")
    sep()
    cible = input("\n  IP ou domaine : ").strip()
    if not cible:
        err("Vide.")
        return

    try:
        ip = socket.gethostbyname(cible)
        ok(f"IP : {ip}")
    except:
        err("Résolution échouée.")
        return

    try:
        ptr = socket.gethostbyaddr(ip)[0]
        ok(f"PTR : {ptr}")
    except:
        warn("Pas de PTR.")

    i("Domaines hébergés sur cette IP...")
    brut = get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}")
    res = [f"IP: {ip}"]

    if brut and "error" not in brut.lower():
        doms = [l.strip() for l in brut.splitlines() if l.strip()]
        ok(f"{len(doms)} domaine(s) trouvé(s) :")
        for d in doms[:25]:
            print(f"  {DIM}→{R} {d}")
        if len(doms) > 25:
            print(f"  {DIM}... +{len(doms)-25} autres{R}")
        res += doms
    else:
        warn("Aucun résultat (limite API ou IP privée).")

    ask_save("reverse_ip", res)


# ─── Réseau local ─────────────────────────────────────────────────────────────

def reseau():
    sep()
    print(f"  {GRAS}RÉSEAU LOCAL{R}")
    sep()
    print()
    res = []

    try:
        h = socket.gethostname()
        ok(f"Machine      : {h}")
        res.append(f"Machine: {h}")
    except: pass

    try:
        ip = socket.gethostbyname(socket.gethostname())
        ok(f"IP locale    : {ip}")
        res.append(f"IP locale: {ip}")
    except: pass

    i("IP publique...")
    brut = get("https://api.ipify.org?format=json")
    if brut:
        try:
            pub = json.loads(brut).get("ip")
            ok(f"IP publique  : {VERT}{pub}{R}")
            res.append(f"IP publique: {pub}")
        except: pass

    try:
        out = subprocess.check_output(["ip","route"], stderr=subprocess.DEVNULL).decode()
        for l in out.splitlines():
            if "default" in l:
                gw = l.split()[2]
                ok(f"Passerelle   : {gw}")
                res.append(f"Passerelle: {gw}")
                break
    except: pass

    try:
        out = subprocess.check_output(["ip","-o","addr","show"], stderr=subprocess.DEVNULL).decode()
        ok("Interfaces :")
        for l in out.splitlines():
            p = l.split()
            if len(p) >= 4:
                print(f"  {DIM}  {p[1]:<12} {p[3]}{R}")
                res.append(f"{p[1]}: {p[3]}")
    except: pass

    ask_save("reseau", res)


# ─── Menu ─────────────────────────────────────────────────────────────────────

MODULES = {
    "1": ("Géolocalisation IP",        geoip),
    "2": ("DNS & WHOIS",               dns_whois),
    "3": ("Scanner de ports",          scan_ports),
    "4": ("Recherche de pseudo",       pseudo),
    "5": ("OSINT E-mail",              email_osint),
    "6": ("Dorks Google",              dorks),
    "7": ("Sous-domaines",             subdomains),
    "8": ("Reverse IP",                reverse_ip),
    "9": ("Réseau local",              reseau),
    "0": ("Quitter",                   None),
}

def main():
    banner()
    while True:
        print(f"  {GRAS}MODULES{R}")
        sep()
        for k, (nom, _) in MODULES.items():
            c = ROUGE if k == "0" else CYAN
            print(f"  {c}[{k}]{R}  {nom}")
        sep()

        choix = input(f"\n  → ").strip()
        if choix not in MODULES:
            err("Choix invalide.")
            input(f"\n  {DIM}Entrée...{R}")
            banner()
            continue

        nom, fn = MODULES[choix]
        if fn is None:
            print(f"\n  {DIM}Fermeture.{R}\n")
            sys.exit(0)

        print()
        try:
            fn()
        except KeyboardInterrupt:
            warn("Interrompu.")

        input(f"\n  {DIM}Entrée pour revenir au menu...{R}")
        banner()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n  {JAUNE}[!]{R} Fermeture.\n")
        sys.exit(0)
