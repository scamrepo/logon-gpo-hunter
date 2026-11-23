# logon-gpo-hunter

Localise la ou les GPO responsables d'un `STATUS_LOGON_TYPE_NOT_GRANTED` et liste, **droit par droit** et **machine par machine**, les groupes autorisés ou refusés à ouvrir une session.

Pensé pour répondre vite à une seule question en audit Active Directory : *pourquoi ce compte se fait-il refuser en WinRM / RDP / SMB sur cette machine, et quelle GPO applique ce refus ?*

> Contexte et analyse détaillée (modèle en tiers, faiblesse structurelle des `SeDeny*LogonRight`, contournement par conversion de groupe, détection) :
> [**Contourner les User Rights Assignment comme implémentation du Tiering**](https://scamrepo.github.io/).

---

## Pourquoi

Le cloisonnement en tiers est souvent implémenté via les droits de logon `SeDeny*LogonRight` distribués par GPO. Ce mécanisme **échoue « ouvert »** : le refus ne s'applique que si un SID listé est présent dans le jeton d'accès, et seuls les **groupes de sécurité** comptent. Avant d'attaquer ou de durcir, il faut donc cartographier : quelle GPO pose quel refus, sur quelle OU, pour quels groupes.

`logon-gpo-hunter` fait cette cartographie **avec un simple compte du domaine**, sans admin local, et de façon discrète :

- Énumération **LDAP** des GPO (`groupPolicyContainer`) et de leurs liens (`gPLink`).
- Lecture **SMB** de la section `[Privilege Rights]` de chaque `GptTmpl.inf` dans SYSVOL.
- Résolution des SID en noms de comptes/groupes.
- Rendu « droit par droit », plus une **vue ciblée** par machine qui remonte la chaîne d'OU, du conteneur le plus proche vers la racine.



---

## Installation

```bash
pip install impacket ldap3
```

```bash
chmod +x logon-gpo-hunter.py
```

---

## Utilisation

### Vue globale (toutes les GPO qui définissent un droit de logon)

```bash
./logon-gpo-hunter.py --dc 10.0.0.1 -d corp.local -u analyst -p 'Passw0rd!'
```

### Vue ciblée sur une machine

Montre uniquement les GPO qui touchent la machine, dans l'ordre de précédence :

```bash
./logon-gpo-hunter.py --dc dc01.corp.local -d corp.local -u analyst -p 'Passw0rd!' --target WKS-T2-07
```

### Pass-the-hash

```bash
./logon-gpo-hunter.py --dc 10.0.0.1 -d corp.local -u analyst -H :e52c...NThash
```

### Kerberos 

```bash
export KRB5CCNAME=/tmp/analyst.ccache
./logon-gpo-hunter.py --dc dc01.corp.local -d corp.local -u analyst -k
```

> En Kerberos, `--dc` doit être le **FQDN** du DC (pas une IP), le TGT doit être valide (`KRB5CCNAME`) et l'horloge synchronisée.

### SYSVOL hors-ligne (quand le 445 est fermé)

Rapatriez le dossier `Policies` par un autre canal, puis :

```bash
./logon-gpo-hunter.py --dc 10.0.0.1 -d corp.local -u analyst -p 'Passw0rd!' \
    --sysvol local --sysvol-path ./Policies
```

---

## Options

| Option | Description |
|---|---|
| `--dc` | IP ou FQDN du DC (**FQDN requis** en Kerberos). |
| `-d`, `--domain` | Nom de domaine (ex. `corp.local`). |
| `-u`, `--user` | Compte du domaine. |
| `-p`, `--password` | Mot de passe. |
| `-H`, `--hashes` | `[LM:]NT` pour pass-the-hash. |
| `-k`, `--kerberos` | Auth Kerberos via `KRB5CCNAME` (contourne l'EPA LDAP). |
| `--target` | Nom d'une machine : vue restreinte aux GPO qui la touchent. |
| `--ldaps` | LDAP sur TLS (port 636). |
| `--sysvol {smb,local}` | Source des `GptTmpl.inf` : `smb` (défaut) ou `local`. |
| `--sysvol-path` | Dossier `Policies` déjà récupéré (avec `--sysvol local`). |
| `--no-color` | Désactive la couleur ANSI. |

---

## Droits analysés

**Autorisations** (`SeAllow*` / logon rights) :

| Droit | Signification |
|---|---|
| `SeNetworkLogonRight` | Accès réseau — SMB / WinRM (type 3) |
| `SeRemoteInteractiveLogonRight` | Bureau à distance — RDP (type 10) |
| `SeInteractiveLogonRight` | Ouverture locale — console (type 2) |
| `SeBatchLogonRight` | Tâche planifiée (type 4) |
| `SeServiceLogonRight` | Service (type 5) |

**Refus** (`SeDeny*`) : contreparties de chacun des droits ci-dessus. Un `SeDeny*` l'emporte toujours sur le `Allow` correspondant.

---

## Lecture de la sortie

- Les blocs `[GPO]` listent le nom, le GUID, les OU liées (avec les marqueurs `DESACTIVE` / `ENFORCED`) et, par droit, les membres `AUTORISE` (vert) ou `REFUSE` (rouge).
- `(VIDE = personne)` sur un droit signale une liste explicitement vide.
- `(SID non resolu)` : SID absent de l'annuaire (groupe local, SID orphelin, forêt externe).
- La **vue cible** rappelle la règle de précédence : `ENFORCED > OU proche > OU parente`, et `SeDeny*` prime sur `Allow`.

Si SYSVOL n'a pas pu être lu (445 fermé et pas de mode `local`), l'outil liste quand même les GPO et leurs liens, mais sans le détail des droits.

---

## Notes OPSEC

- Collecte **LDAP + SMB en lecture seule** depuis un compte peu privilégié : discret, pas d'admin local requis.
- Contrairement à l'alternative RPC par hôte (`LsaEnumerateAccountsWithUserRight`), aucune énumération bruyante machine par machine.
- Lecture seule : l'outil ne modifie rien dans l'annuaire ni dans SYSVOL.

---

## Avertissement

Outil d'audit et de recherche en sécurité. À n'utiliser que sur des environnements dont vous avez l'autorisation explicite (engagement de pentest, lab, CTF). L'auteur décline toute responsabilité en cas d'usage hors de ce cadre.

---
