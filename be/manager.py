import logging
import sys
import os
from urllib.parse import urlparse
from datetime import datetime

# Importaciones de todos los módulos
from .utils.config_loader import load_config
from .modules.recon import ReconModule
from .modules.probing import ProbingModule
from .modules.urls import UrlsModule

logger = logging.getLogger(__name__)

class Manager:
    def __init__(self, args):
        self.args = args
        self.config = load_config()

        if self.args.output:
            base_output_dir = self.config.get('RECON', 'DEFAULT_OUTPUT_DIR', fallback='outputs/')
            self.args.output = os.path.join(base_output_dir, self.args.output)
        
        # <<< CAMBIO CLAVE: recon3 ahora normaliza el dominio como recon1 y recon2 >>>
        # Solo --urls necesita los objetivos tal cual.
        is_direct_url_mode = self.args.urls
        self.targets = self._load_targets(normalize_to_root_domain=not is_direct_url_mode)

    def _load_targets(self, normalize_to_root_domain=True):
        """Carga objetivos y opcionalmente los normaliza a dominios raíz."""
        targets = []
        if self.args.url:
            target_line = self.args.url.strip()
            if normalize_to_root_domain:
                targets.append(self._normalize_domain(target_line))
            else:
                targets.append(target_line)
        if self.args.list:
            try:
                with open(self.args.list, 'r') as f:
                    for line in f:
                        if line.strip():
                            if normalize_to_root_domain:
                                targets.append(self._normalize_domain(line.strip()))
                            else:
                                targets.append(line.strip())
            except IOError as e:
                logger.error(f"No se pudo leer el archivo de lista: {e}")
                sys.exit(1)
        
        unique_targets = sorted(list(set(filter(None, targets))))
        logger.info(f"Objetivos cargados: {len(unique_targets)}")
        return unique_targets

    def _normalize_domain(self, target):
        """Extrae el dominio de una URL si es necesario."""
        if '://' in target:
            return urlparse(target).netloc
        return target.strip('/')

    def run(self):
        """Orquesta la ejecución según los flags proporcionados."""
        # <<< CAMBIO CLAVE: recon3 ahora usa el mismo flujo que recon1 y recon2 >>>
        if self.args.recon1 or self.args.recon2 or self.args.recon3 or self.args.all:
            self._run_reconnaissance_pipeline()
        elif self.args.urls:
            self._run_direct_urls_pipeline()

    def _run_reconnaissance_pipeline(self):
        """Ejecuta el flujo completo de descubrimiento para cada dominio raíz."""
        logger.info("[+] Iniciando en modo Reconocimiento...")
        for target_domain in self.targets:
            # Ahora el output se crea por objetivo, que es más ordenado.
            run_output_dir = self._setup_output_directory_for_target(target_domain)
            logger.info(f"\n=======================================================")
            logger.info(f"🎯 Iniciando escaneo para el objetivo: {target_domain}")
            
            # 1. BÚSQUEDA DE SUBDOMINIOS (Para recon1, recon2 y AHORA TAMBIÉN recon3)
            results = ReconModule(target_domain, self.args, self.config, run_output_dir).run()
            subdomains_to_probe = results.get('subdomains', [])
            
            live_hosts = []
            if subdomains_to_probe:
                # 2. SONDEO de los subdominios encontrados
                live_hosts = self._run_probing(target_domain, subdomains_to_probe, run_output_dir)
            
            # 3. Búsqueda de URLs (si se especifica)
            if self.args.urls and live_hosts:
                self._run_urls(target_domain, live_hosts, run_output_dir)

            logger.info(f"✅ Escaneo finalizado para: {target_domain}")

    def _run_direct_urls_pipeline(self):
        """Ejecuta SOLO el módulo de URLs directamente sobre la lista de entrada."""
        logger.info("[+] Iniciando en modo Directo (solo --urls)...")
        if not self.targets:
            logger.warning("[!] La lista de entrada está vacía. Nada que procesar.")
            return

        output_dir = self._setup_main_output_directory()
        project_name = os.path.basename(os.path.normpath(self.args.output))
        self._run_urls(project_name, self.targets, output_dir)
        logger.info(f"✅ Procesamiento de URLs finalizado para el proyecto: {project_name}")

    def _run_probing(self, target_name, hosts, output_dir):
        """Función auxiliar para ejecutar el módulo de sondeo."""
        logger.info(f"  [+] Ejecutando Módulo PROBING sobre {len(hosts)} hosts...")
        
        # Esta lógica ya era correcta y ahora funcionará como esperas.
        if self.args.recon3:
            probing_mode = 'fast'
        elif self.args.recon2 or self.args.all:
            probing_mode = 'full'
        else: # Por defecto para recon1
            probing_mode = 'light'
            
        probing_module = ProbingModule(target_name, self.args, self.config, hosts, probing_mode)
        probing_results = probing_module.run(output_dir)
        
        if probing_results and 'positives' in probing_results:
            return [item['url'] for item in probing_results.get('positives', [])]
        return []

    def _run_urls(self, target_name, hosts, output_dir):
        """Función auxiliar para ejecutar el módulo de URLs."""
        logger.info(f"  [+] Ejecutando Módulo URLS sobre {len(hosts)} hosts/dominios de la lista...")
        urls_module = UrlsModule(target_name, self.args, self.config, hosts)
        urls_module.run(output_dir)

    def _setup_main_output_directory(self):
        """Prepara el directorio de salida principal."""
        output_dir = self.args.output
        if not output_dir:
            output_dir = os.path.join('outputs', f"run_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        os.makedirs(output_dir, exist_ok=True)
        logger.info(f"💾 Resultados se guardarán en: {output_dir}")
        return output_dir

    def _setup_output_directory_for_target(self, target_name):
        """Prepara un subdirectorio para un objetivo específico."""
        main_output_dir = self._setup_main_output_directory()
        safe_target_name = target_name.replace('.', '_')
        target_dir = os.path.join(main_output_dir, safe_target_name)
        os.makedirs(target_dir, exist_ok=True)
        logger.info(f"💾 Resultados para {target_name} se guardarán en: {target_dir}")
        return target_dir