# 🔴 HACKERS_TCHAD IGMP Protocol Interface 🔴

![HACKERS_TCHAD](https://img.shields.io/badge/Created%20by-HACKERS_TCHAD-red?style=for-the-badge)

Interface graphique avancée d'analyse, de simulation et d'apprentissage du protocole **IGMP (Internet Group Management Protocol)**.

## 🎨 Style Hacker

- Thème **Cyberpunk Hacker** : noir profond, vert néon et rouge alerte
- Police monospace pour l'aspect terminal
- Animations et effets visuels
- Interface inspirée des outils de sécurité réseau

## ⚡ Fonctionnalités

### Composants réseau simulés

- **Source / Serveur multicast** : envoie du trafic multicast vers un groupe
- **Client / Hôte** : rejoint ou quitte des groupes multicast (IGMP Join/Leave)
- **Routeur multicast** : reçoit et traite les messages IGMP, gère les groupes
- **Switch avec IGMP Snooping** : apprend dynamiquement quels ports veulent quel groupe

### Messages IGMP supportés

- `IGMPv1 Membership Report`
- `IGMPv2 Membership Report`
- `IGMPv2 Leave Group`
- `IGMPv2 General Query` (routeur)
- `IGMPv2 Group-Specific Query` (routeur)
- `IGMPv3 Membership Report` (mode INCLUDE/EXCLUDE)

### Fonctionnalités avancées

- 🌐 Visualisation en temps réel du flux de paquets
- 📊 Table des groupes multicast actifs
- 🔍 Table IGMP Snooping du switch (ports/groupes)
- 📝 Logs détaillés avec horodatage
- 🎓 Mode éducatif avec explications
- 🧪 Simulation de scénarios prédéfinis
- 📈 Statistiques de trafic multicast
- ⚙️ Configuration des timers IGMP
- 🔐 Détection d'anomalies et alertes

## 🚀 Installation

```bash
cd hackers_tchad_igmp
pip install -r requirements.txt
```

### Prérequis

- Python 3.8+
- tkinter

## ▶️ Lancement

```bash
python main.py
```

## 🎮 Utilisation

1. Ajoutez des **Sources**, **Clients**, **Routeurs** et **Switches** depuis le panneau de gauche.
2. Connectez les équipements entre eux via le panneau central.
3. Faites rejoindre un **Client** à un groupe multicast (ex: `239.1.1.1`).
4. Lancez l'envoi de trafic depuis une **Source** vers ce groupe.
5. Observez les messages IGMP, les tables de groupes et le snooping en temps réel.

## 📚 Scénarios intégrés

- **Join/Leave basique** : un client rejoint puis quitte un groupe
- **Source active** : envoi continu de trafic multicast
- **Multiple clients** : plusieurs clients rejoignent le même groupe
- **IGMP Snooping** : le switch apprend les ports multicast
- **Leave rapide** : test du mécanisme de leave IGMPv2

## 🛠️ Architecture IGMP

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

## 📝 Notes

- Cet outil est un **simulateur pédagogique** : il ne génère pas de vrai trafic réseau IGMP.
- Il modélise fidèlement le comportement du protocole IGMP v1/v2/v3.
- Créé par **HACKERS_TCHAD** pour l'apprentissage et la démonstration.

## 👤 Auteur

**HACKERS_TCHAD**
