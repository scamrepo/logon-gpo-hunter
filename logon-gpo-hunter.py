#!/usr/bin/env python3
"""logon-gpo-hunter.py — localise la/les GPO responsables d'un
STATUS_LOGON_TYPE_NOT_GRANTED et liste, droit par droit, les groupes
autorises ou refuses, machine par machine.

Depuis une station d'audit :  pip install impacket ldap3
Un simple compte du domaine suffit : la lecture LDAP/SYSVOL n'est pas
soumise au droit de logon refuse sur WinRM/RDP.
"""

import argparse
import os
import re
import ssl
import sys
from io import BytesIO

try:
    from ldap3 import Server, Connection, ALL, NTLM, SUBTREE, Tls, SASL, KERBEROS
except ImportError:
    sys.exit("[!] Manque ldap3 : pip install ldap3")
try:
    from impacket.smbconnection import SMBConnection
except ImportError:
    sys.exit("[!] Manque impacket : pip install impacket")

ALLOW_RIGHTS = {
    "SeNetworkLogonRight":           "Acces reseau — SMB / WinRM (type 3)",
    "SeRemoteInteractiveLogonRight": "Bureau a distance — RDP (type 10)",
    "SeInteractiveLogonRight":       "Ouverture locale — console (type 2)",
    "SeBatchLogonRight":             "Tache planifiee (type 4)",
    "SeServiceLogonRight":           "Service (type 5)",
}
DENY_RIGHTS = {
    "SeDenyNetworkLogonRight":           "REFUS acces reseau (SMB / WinRM)",
    "SeDenyRemoteInteractiveLogonRight": "REFUS RDP",
    "SeDenyInteractiveLogonRight":       "REFUS ouverture locale",
    "SeDenyBatchLogonRight":             "REFUS tache planifiee",
    "SeDenyServiceLogonRight":           "REFUS service",
}
ALL_RIGHTS = {**ALLOW_RIGHTS, **DENY_RIGHTS}

WELLKNOWN = {
    "S-1-1-0": "Everyone",
    "S-1-5-7": "Anonymous",
    "S-1-5-9": "Enterprise Domain Controllers",
    "S-1-5-11": "Utilisateurs authentifies",
    "S-1-5-18": "SYSTEM",
    "S-1-5-19": "LOCAL SERVICE",
    "S-1-5-20": "NETWORK SERVICE",
    "S-1-5-32-544": "Administrators",
    "S-1-5-32-545": "Users",
    "S-1-5-32-546": "Guests",
    "S-1-5-32-551": "Backup Operators",
    "S-1-5-32-555": "Remote Desktop Users",
    "S-1-5-32-580": "Remote Management Users",
}

USE_COLOR = sys.stdout.isatty()
def _c(t, code): return "\033[" + code + "m" + t + "\033[0m" if USE_COLOR else t
def RED(t):  return _c(t, "91")
def GRN(t):  return _c(t, "92")
def YEL(t):  return _c(t, "93")
def CYN(t):  return _c(t, "96")
def BOLD(t): return _c(t, "1")


def sid_to_str(raw):
    if isinstance(raw, str) and raw.startswith("S-1-"):
        return raw
    b = bytes(raw)
    rev, count = b[0], b[1]
    authority = int.from_bytes(b[2:8], "big")
    sid = "S-" + str(rev) + "-" + str(authority)
    for i in range(count):
        off = 8 + i * 4
        sid += "-" + str(int.from_bytes(b[off:off + 4], "little"))
    return sid


def connect_ldap(dc, domain, user, password, lmhash, nthash, ldaps, kerberos):
    port = 636 if ldaps else 389
    tls = Tls(validate=ssl.CERT_NONE) if ldaps else None
    server = Server(dc, port=port, use_ssl=ldaps, tls=tls, get_info=ALL)
    if kerberos:
        conn = Connection(server, authentication=SASL, sasl_mechanism=KERBEROS)
    else:
        pw = lmhash + ":" + nthash if nthash else password
        conn = Connection(server, user=domain + "\\" + user, password=pw, authentication=NTLM)

    try:
        ok = conn.bind()
    except Exception as e:
        if kerberos:
            sys.exit("[!] Bind Kerberos impossible (" + e.__class__.__name__ + "). "
                     "Verifier KRB5CCNAME (TGT valide), --dc en FQDN et l'horloge.")
        raise

    if not ok:
        res = conn.result
        msg = str(res.get("message", "")) if isinstance(res, dict) else str(res)
        hint = ""
        if "80090346" in msg:
            hint = " -> LDAP channel binding (EPA) impose. Relancer en Kerberos (-k)."
        elif "52e" in msg:
            hint = " -> mauvais identifiant/mot de passe."
        elif "533" in msg:
            hint = " -> compte desactive."
        elif "775" in msg:
            hint = " -> compte verrouille."
        sys.exit("[!] Echec bind LDAP : " + str(res) + hint)
    return conn


def base_dn_of(conn, domain):
    try:
        return conn.server.info.other["defaultNamingContext"][0]
    except Exception:
        return ",".join("DC=" + p for p in domain.split("."))


def build_sid_map(conn, base_dn):
    conn.search(base_dn,
                "(|(objectClass=user)(objectClass=group)(objectClass=computer))",
                search_scope=SUBTREE, attributes=["sAMAccountName", "objectSid"])
    m = {}
    for e in conn.entries:
        if "objectSid" not in e or not e["objectSid"].raw_values:
            continue
        sid = sid_to_str(e["objectSid"].raw_values[0])
        m[sid] = str(e.sAMAccountName) if "sAMAccountName" in e else sid
    return m


def resolve(token, sid_map):
    if not token.startswith("S-1-"):
        return token
    if token in WELLKNOWN:
        return WELLKNOWN[token]
    return sid_map.get(token, token + YEL("  (SID non resolu)"))


def get_gpos(conn, base_dn):
    pol_dn = "CN=Policies,CN=System," + base_dn
    conn.search(pol_dn, "(objectClass=groupPolicyContainer)", search_scope=SUBTREE,
                attributes=["displayName", "cn", "gPCFileSysPath"])
    gpos = {}
    for e in conn.entries:
        guid = str(e.cn).upper()
        gpos[guid] = {
            "name": str(e.displayName),
            "guid": guid,
            "syspath": str(e.gPCFileSysPath),
            "rights": {},
            "links": [],
        }
    return gpos


LINK_RE = re.compile(r"\[LDAP://(?P<dn>[^;]+);(?P<opt>\d+)\]", re.IGNORECASE)


def attach_links(conn, base_dn, gpos):
    conn.search(base_dn, "(|(objectClass=organizationalUnit)(objectClass=domainDNS))",
                search_scope=SUBTREE, attributes=["gPLink", "distinguishedName"])
    for e in conn.entries:
        gplink = str(e.gPLink) if ("gPLink" in e and e.gPLink) else ""
        ou_dn = str(e.distinguishedName)
        for mo in LINK_RE.finditer(gplink):
            opt = int(mo.group("opt"))
            gm = re.search(r"\{[0-9A-Fa-f\-]+\}", mo.group("dn"))
            if not gm:
                continue
            guid = gm.group(0).upper()
            if guid in gpos:
                gpos[guid]["links"].append((ou_dn, not (opt & 1), bool(opt & 2)))


def smb_read_gptmpl(smb, syspath):
    parts = syspath.replace("/", "\\").split("\\")
    low = [p.lower() for p in parts]
    if "sysvol" not in low:
        return None
    idx = low.index("sysvol")
    rel = "\\".join(parts[idx + 1:]) + r"\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
    buf = BytesIO()
    try:
        smb.getFile("SYSVOL", rel, buf.write)
    except Exception:
        return None
    return _decode(buf.getvalue())


def _decode(data):
    for enc in ("utf-16", "utf-8-sig", "latin-1"):
        try:
            return data.decode(enc)
        except Exception:
            continue
    return None


def local_read_gptmpl(policies_dir, guid):
    sub = os.path.join("Machine", "Microsoft", "Windows NT", "SecEdit", "GptTmpl.inf")
    cand = os.path.join(policies_dir, guid, sub)
    if not os.path.isfile(cand) and os.path.isdir(policies_dir):
        want = guid.strip("{}").upper()
        for name in os.listdir(policies_dir):
            if name.strip("{}").upper() == want:
                cand = os.path.join(policies_dir, name, sub)
                break
    if not os.path.isfile(cand):
        return None
    with open(cand, "rb") as f:
        return _decode(f.read())


def parse_logon_rights(text):
    out = {}
    in_sec = False
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("["):
            in_sec = (s.lower() == "[privilege rights]")
            continue
        if in_sec and "=" in s:
            k, _, v = s.partition("=")
            k = k.strip()
            if k in ALL_RIGHTS:
                out[k] = [x.strip().lstrip("*") for x in v.split(",") if x.strip()]
    return out


def ou_chain(comp_dn, base_dn):
    chain, parts = [], comp_dn.split(",")
    for i in range(1, len(parts)):
        dn = ",".join(parts[i:])
        chain.append(dn)
        if dn.lower() == base_dn.lower():
            break
    return chain


def print_gpo(g, sid_map):
    print()
    print(GRN("[GPO] " + g["name"]))
    print("      GUID   : " + g["guid"])
    if g["links"]:
        for ou_dn, enabled, enforced in g["links"]:
            flags = []
            if not enabled:
                flags.append(RED("DESACTIVE"))
            if enforced:
                flags.append(YEL("ENFORCED"))
            tag = (" [" + ", ".join(flags) + "]") if flags else ""
            print("      Lie a : " + ou_dn + tag)
    else:
        print(YEL("      Lie a : (aucun lien direct trouve)"))
    for right, members in g["rights"].items():
        is_deny = right.startswith("SeDeny")
        label = right + "  (" + ALL_RIGHTS[right] + ")"
        print("        - " + (RED(label) if is_deny else label))
        if not members:
            print(RED("            (VIDE = personne)"))
        for m in members:
            name = resolve(m, sid_map)
            print("            " + name + (RED("  REFUSE") if is_deny else GRN("  AUTORISE")))


def main():
    ap = argparse.ArgumentParser(
        description="Localise la GPO responsable d'un STATUS_LOGON_TYPE_NOT_GRANTED")
    ap.add_argument("--dc", required=True, help="IP ou FQDN du DC")
    ap.add_argument("-d", "--domain", required=True, help="Domaine")
    ap.add_argument("-u", "--user", required=True)
    ap.add_argument("-p", "--password", default=None)
    ap.add_argument("-H", "--hashes", default=None, help="[LM:]NT pour pass-the-hash")
    ap.add_argument("-k", "--kerberos", action="store_true",
                    help="Auth Kerberos (contourne le LDAP channel binding). TGT via KRB5CCNAME, --dc en FQDN.")
    ap.add_argument("--target", default=None,
                    help="Nom d'une machine : montre uniquement les GPO qui la touchent")
    ap.add_argument("--ldaps", action="store_true", help="LDAP sur TLS (636)")
    ap.add_argument("--sysvol", choices=["smb", "local"], default="smb",
                    help="Source des GptTmpl.inf : smb (defaut) ou local si le 445 est ferme")
    ap.add_argument("--sysvol-path", help="Dossier Policies deja recupere (avec --sysvol local)")
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args()

    global USE_COLOR
    if args.no_color:
        USE_COLOR = False

    lmhash = nthash = ""
    if args.hashes:
        if ":" in args.hashes:
            lmhash, nthash = args.hashes.split(":", 1)
        else:
            nthash = args.hashes
        lmhash = lmhash or "aad3b435b51404eeaad3b435b51404ee"
    if not args.kerberos and not args.password and not nthash:
        sys.exit("[!] Fournir -p <pass> ou -H [LM:]NT (ou -k avec un TGT)")
    if args.kerberos and re.match(r"^\d+\.\d+\.\d+\.\d+$", args.dc):
        print(YEL("[!] Kerberos : --dc doit etre le FQDN du DC, pas une IP."))

    conn = connect_ldap(args.dc, args.domain, args.user, args.password,
                        lmhash, nthash, args.ldaps, args.kerberos)
    base_dn = base_dn_of(conn, args.domain)
    print(CYN("[*] Base DN : " + base_dn))
    sid_map = build_sid_map(conn, base_dn)
    print(CYN("[*] " + str(len(sid_map)) + " principals charges"))
    gpos = get_gpos(conn, base_dn)
    attach_links(conn, base_dn, gpos)
    print(CYN("[*] " + str(len(gpos)) + " GPO trouvees"))

    smb = None
    sysvol_read = False
    if args.sysvol == "local":
        if not args.sysvol_path or not os.path.isdir(args.sysvol_path):
            sys.exit("[!] --sysvol local exige --sysvol-path <dossier Policies>")
        print(CYN("[*] Lecture hors-ligne depuis " + args.sysvol_path))
        for g in gpos.values():
            text = local_read_gptmpl(args.sysvol_path, g["guid"])
            if text:
                g["rights"] = parse_logon_rights(text)
        sysvol_read = True
    else:
        try:
            smb = SMBConnection(args.dc, args.dc)
            if args.kerberos:
                smb.kerberosLogin(args.user, args.password or "", args.domain,
                                  lmhash, nthash, aesKey="", kdcHost=args.dc, useCache=True)
            else:
                smb.login(args.user, args.password or "", args.domain, lmhash, nthash)
            sysvol_read = True
        except Exception as e:
            print(RED("[!] SMB (445) indisponible : " + e.__class__.__name__))
            print(YEL("    Rapatrier le dossier Policies, puis --sysvol local --sysvol-path ./Policies"))
        if smb is not None and sysvol_read:
            for g in gpos.values():
                text = smb_read_gptmpl(smb, g["syspath"])
                if text:
                    g["rights"] = parse_logon_rights(text)

    relevant = {k: v for k, v in gpos.items() if v["rights"]}

    print()
    print(BOLD("=" * 72))
    print(BOLD(" GPO QUI DEFINISSENT UN DROIT DE LOGON"))
    print(BOLD("=" * 72))
    if not sysvol_read:
        print(RED("  SYSVOL non lu (445 ferme) : droits exacts non extraits."))
        for g in gpos.values():
            links = "; ".join(ou for ou, en, _ in g["links"] if en) or "(non liee)"
            print("    - " + g["name"] + "  " + g["guid"])
            print("        liee a: " + links)
    elif not relevant:
        print(YEL("  Aucune GPO ne definit de droit de logon explicite dans SYSVOL."))
        print(YEL("  => le refus vient des valeurs par defaut (appartenance a un groupe local)."))
    for g in relevant.values():
        print_gpo(g, sid_map)

    if args.target:
        print()
        print(BOLD("=" * 72))
        print(BOLD(" VUE CIBLE : " + args.target))
        print(BOLD("=" * 72))
        conn.search(base_dn,
                    "(&(objectClass=computer)(|(sAMAccountName=" + args.target + "$)"
                    "(dNSHostName=" + args.target + ")(cn=" + args.target + ")))",
                    search_scope=SUBTREE, attributes=["distinguishedName", "dNSHostName"])
        if not conn.entries:
            print(YEL("  Machine introuvable dans l'annuaire."))
        else:
            comp_dn = str(conn.entries[0].distinguishedName)
            print("  DN machine : " + comp_dn)
            chain = ou_chain(comp_dn, base_dn)
            src = relevant if (sysvol_read and relevant) else gpos
            applied = [(g, ou, enf)
                       for g in src.values()
                       for (ou, en, enf) in g["links"]
                       if en and ou in chain]
            if not applied:
                print(YEL("  Aucune GPO liee a la chaine d'OU de cette machine."))
            else:
                print(GRN("  GPO applicables (du conteneur le plus proche vers la racine) :"))
                for g, ou, enf in applied:
                    tag = YEL(" [ENFORCED]") if enf else ""
                    print("    - " + g["name"] + "  @ " + ou + tag)
                    if g["rights"]:
                        for right, members in g["rights"].items():
                            who = ", ".join(resolve(m, sid_map) for m in members) or RED("(vide)")
                            lab = RED(right) if right.startswith("SeDeny") else right
                            print("        " + lab + ": " + who)
            print()
            print(CYN("  Precedence : ENFORCED > OU proche > OU parente ;"))
            print(CYN("  un SeDeny* l'emporte toujours sur le Allow correspondant."))

    conn.unbind()
    if smb is not None:
        try:
            smb.close()
        except Exception:
            pass


if __name__ == "__main__":
    main()

