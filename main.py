#!/usr/bin/env python3
import argparse
import sys
import os
import logging
from datetime import datetime
from be.manager import Manager
# Necesitas importar el módulo sys para usar sys.exit en validate_args

# ─── Banner ───────────────────────────────────────────────────────────────
def banner():
    print(r"""
  ____             ____                      _         
 | __ )  _   _   | __ )  _   _  _ __   ___ | |_  _ __ 
 |  _ \ | | | |  |  _ \ | | | || '_ \ / __|| __|| '__|
 | |_) || |_| |  | |_) || |_| || | | |\__ \| |_ | |   
 |____/  \__, |  |____/  \__,_||_| |_||___/ \__||_|   
         |___/                BugBounty Framework v0.1 
    """)

# ─── Configuración de Logging ─────────────────────────────────────────────
def setup_logging(verbose=False, output_dir="logs"):
    """Configura el sistema de logging"""
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    log_level = logging.DEBUG if verbose else logging.INFO
    log_file = os.path.join(output_dir, f"bugbounty_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
    
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )
    return logging.getLogger(__name__)

# ─── Validación de Argumentos ─────────────────────────────────────────────
def validate_args(args):
    """Valida los argumentos de entrada"""
    if args.list and not os.path.isfile(args.list):
        print(f"❌ Error: El archivo {args.list} no existe")
        sys.exit(1)
    
    # if args.output and not os.path.exists(args.output):
    #     os.makedirs(args.output, exist_ok=True)
    
    # Validar que al menos un módulo esté seleccionado
    # 🟢 CORRECCIÓN CLAVE: Reemplazamos args.recon con args.recon1 y args.recon2
    if not any([args.recon1, args.recon2, args.recon3, args.subdomains, args.urls, args.all]):
        print("❌ Error: Debes seleccionar al menos un módulo de escaneo")
        # También actualizamos el mensaje de ayuda para que el usuario vea la nueva opción.
        print("   Usa --recon1, --recon2, --recon3, --subdomains, --urls o --all")
        sys.exit(1)

# ─── Argumentos CLI Mejorados ─────────────────────────────────────────────
def parse_args():
    parser = argparse.ArgumentParser(
        description="Herramienta de reconocimiento y escaneo Bug Bounty.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  %(prog)s -l domains.txt --urls --output results/
  %(prog)s -u https://example.com --verbose --threads 10
        """
    )
    
    # Argumentos de objetivo
    target_group = parser.add_argument_group('Targets')
  
    target_group.add_argument("-u", "--url", help="URL específica a analizar")
    target_group.add_argument("-l", "--list", help="Archivo con lista de dominios o URLs")
    
    # Módulos de escaneo
    modules_group = parser.add_argument_group('Scan Modules')
    modules_group.add_argument("--recon1", action="store_true", help="Ejecutar reconocimiento pasivo rápido (Subdominios)")
    modules_group.add_argument("--recon2", action="store_true", help="Ejecutar reconocimiento pasivo profundo (Recon1 + Probing con Httpx)")
    modules_group.add_argument("--recon3", action="store_true", help="Ejecutar reconocimiento pasivo muy rapido (Probing con Httpx simple)")
    modules_group.add_argument("--subdomains", action="store_true", help="Descubrimiento de subdominios (Activo/Bruteforce)")
    modules_group.add_argument("--urls", action="store_true", help="Extracción y análisis de URLs")
    modules_group.add_argument("--all", action="store_true", help="Ejecutar todos los módulos (Equivalente a --recon2 + --subdomains + --urls)")

    
    # Configuración
    config_group = parser.add_argument_group('Configuration')
    config_group.add_argument("-t", "--threads", type=int, default=5, help="Número de hilos (default: 5)")
    config_group.add_argument("-o", "--output", help="Directorio de salida para resultados")
    # 🟢 CORRECCIÓN: Aumentar el timeout por defecto
    config_group.add_argument("--timeout", type=int, default=30, help="Timeout para requests (default: 30)")
    config_group.add_argument("--user-agent", help="User-Agent personalizado")
    
    # Verbosity
    config_group.add_argument("-v", "--verbose", action="store_true", help="Mostrar más detalles")
    config_group.add_argument("--debug", action="store_true", help="Modo debug")
    
    args = parser.parse_args()

    # Validar que se proporcione al menos un objetivo
    if not any([args.url, args.list]):
        parser.print_help()
        sys.exit(1)
        
    validate_args(args)
    
    return args

# ─── Manejo de Excepciones ────────────────────────────────────────────────
# Se mantiene el manejo simplificado que usa el logger para el traceback
def handle_exceptions(func):
    """Decorator para manejo global de excepciones"""
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except KeyboardInterrupt:
            print("\n⚠️  Escaneo interrumpido por el usuario")
            sys.exit(0)
        except Exception as e:
            # Ahora usamos logging para el traceback si el log está en DEBUG
            logger = logging.getLogger(__name__)
            logger.critical(f"Error crítico en la aplicación: {e}", exc_info=True)
            print(f"❌ Error crítico: {e}. Revisa el log para el traceback completo.")
            sys.exit(1)
    return wrapper

# ─── Main ─────────────────────────────────────────────────────────────────
@handle_exceptions
def main():
    banner()
    args = parse_args()
    
    # Configurar logging
    logger = setup_logging(args.verbose or args.debug)
    
    logger.info("Iniciando BugBounty Framework")
    logger.debug(f"Argumentos: {args}")
    
    # Mostrar configuración
    if args.verbose:
        print(f"🔧 Configuración:")
        print(f"   URL: {args.url}") 
        print(f"   Lista: {args.list}")
        print(f"   Threads: {args.threads}")
        print(f"   Output: {args.output}")
        print()
    
    # Inicializar y ejecutar manager
    manager = Manager(args)
    manager.run()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n⚠️  Escaneo interrumpido por el usuario")
        sys.exit(0)
    except Exception as e:
        print(f"❌ Error crítico: {e}")
        sys.exit(1)