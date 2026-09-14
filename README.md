#  HACKERS_TCHAD IGMP Protocol Interface 
<img width="1248" height="832" alt="OIG1 (5)" src="https://github.com/user-attachments/assets/319c59a9-82b3-4b83-8e84-32ab9ebf22de" />

![HACKERS_TCHAD](https://img.shields.io/badge/Created%20by-HACKERS_TCHAD-red?style=for-the-badge)

<img width="800" height="488" alt="IGMP-snooping" src="https://github.com/user-attachments/assets/aa598234-45a5-4ba5-8fc9-bb4bc172a4a1" />


**Créé par HACKERS_TCHAD**

Analyseur et moniteur IGMP/Multicast professionnel capable de capturer et de générer du **vrai trafic réseau**.

##  Capacités avancées

-  Capture **live** de paquets IGMP et multicast sur une interface réseau
-  Génération de paquets IGMP réels : Join, Leave, Query, Report v1/v2/v3
-  Envoi et réception de flux multicast UDP réels
-  Analyse détaillée des paquets (hex dump, champs IGMP)
-  Table IGMP dynamique et IGMP Snooping simulé
-  Export PCAP des captures
-  Statistiques temps réel avec graphiques


## 🛠️ Composants

| Rôle | Description |
|------|-------------|
| **Source Multicast** | Émet du trafic UDP vers un groupe 239.x.x.x |
| **Client/Hôte** | Rejoint/quitte des groupes, reçoit le multicast |
| **Routeur Multicast** | Écoute les IGMP et envoie des Queries |
| **Switch Snooping** | Apprend les associations ports/groupes |
| **Sniffer** | Capture tout le trafic IGMP/multicast de l'interface |

## 📦 Installation

```bash
cd hackers_tchad_igmp_pro
pip install -r requirements.txt
```

### Prérequis

- Python 3.9+
- tkinter
- **Privilèges root/admin** pour la capture de paquets avec scapy

Sous Linux :
```bash
sudo apt install python3-tk python3-scapy
```

##  Lancement

```bash
sudo python main.py
```

Sous Windows, exécutez le terminal en **administrateur**.

##  Utilisation rapide

1. Sélectionnez votre **interface réseau** dans le menu déroulant.
2. Cliquez sur **Start Sniffer** pour capturer le trafic IGMP live.
3. Activez un ou plusieurs rôles (Client, Routeur, Source, Switch).
4. Faites **Join** un client sur un groupe multicast.
5. Envoyez du trafic depuis une Source vers ce groupe.
6. Observez les paquets IGMP, les tables et les statistiques.

##  Export

- **Export PCAP** : sauvegardez les paquets capturés dans un fichier `.pcap`
- **Export Logs** : sauvegardez les logs texte
- **Export CSV** : exportez les statistiques

## 🌐 Groupes multicast

Exemples de groupes privés utilisables :
- `239.255.1.1`
- `239.1.2.3`
- `224.0.0.2` (tous les routeurs)
- `224.0.0.1` (tous les systèmes)

## 👤 Auteur

**HACKERS_TCHAD**

```
┌─────────────┐         ┌─────────────┐
│   SOURCE    │────────▶│   ROUTEUR   │
│  (Serveur)  │  Data   │  Multicast  │
└─────────────┘         └──────┬──────┘
                               │ IGMP Queries/Reports
                        ┌──────┴──────┐
                        │    SWITCH   │
                        │ IGMP Snooping│
                        └──────┬──────┘
                               │
                    ┌─────────┼─────────┐
                    ▼         ▼         ▼
                 CLIENT 1  CLIENT 2  CLIENT 3
```

## 👤 Auteur

**HACKERS_TCHAD**
