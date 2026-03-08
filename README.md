# Termux-Osint-Mils

```
  ███╗   ███╗██╗██╗     ███████╗
  ████╗ ████║██║██║     ██╔════╝
  ██╔████╔██║██║██║     ███████╗
  ██║╚██╔╝██║██║██║     ╚════██║
  ██║ ╚═╝ ██║██║███████╗███████║
  ╚═╝     ╚═╝╚═╝╚══════╝╚══════╝
```

Multi-tools OSINT en ligne de commande, entièrement en français, pensé pour **Termux** et Linux.

---

## Modules

| #  | Nom                    | Description                                          |
|----|------------------------|------------------------------------------------------|
| 1  | Géolocalisation IP     | Pays, ville, FAI, ASN, coordonnées, fuseau horaire   |
| 2  | DNS & WHOIS            | Enregistrements A / MX / NS / TXT + données WHOIS    |
| 3  | Scanner de ports       | Ports courants ou plage manuelle                     |
| 4  | Recherche de pseudo    | Vérification sur 17 plateformes                      |
| 5  | OSINT E-mail           | MX, Gravatar, HaveIBeenPwned                         |
| 6  | Dorks Google           | Génération de dorks prêts à l'emploi                 |
| 7  | Sous-domaines          | Brute-force DNS                                      |
| 8  | Reverse IP             | PTR + domaines hébergés sur une IP                   |
| 9  | Réseau local           | IP locale / publique, passerelle, interfaces         |

---

## Installation

```bash
pkg update && pkg upgrade -y
pkg install python dnsutils git -y
git clone https://github.com/Mils-root/Termux-Osint-Mils.git
cd Termux-Osint-Mils
python osint_toolkit.py
```

Aucune dépendance externe — Python standard uniquement.

---

## Utilisation

Lance le script et navigue avec les numéros. Les résultats peuvent être exportés en `.txt` après chaque module.

---

## Avertissement

À utiliser uniquement sur des systèmes dont vous êtes propriétaire ou avec une autorisation explicite. Toute utilisation illégale est sous l'entière responsabilité de l'utilisateur.

---

**Mils** — [github.com/Mils-root](https://github.com/Mils-root)

