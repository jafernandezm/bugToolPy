# be/modules/urls.py

import logging
import os
import re
from urllib.parse import urlparse
from .utils.helpers import execute_command

logger = logging.getLogger(__name__)

class UrlsModule:
    def __init__(self, target_project_name, args, config, hosts):
        self.project_name = target_project_name
        self.args = args
        self.config = config
        self.hosts = hosts
        self.patterns = self._load_patterns()

    def _load_patterns(self):
        """Carga y compila los patrones regex desde el archivo de configuración."""
        patterns = {}
        if self.config.has_section('URL_PATTERNS'):
            for key, pattern in self.config.items('URL_PATTERNS'):
                try:
                    patterns[key] = re.compile(pattern, re.IGNORECASE)
                except re.error as e:
                    logger.error(f"   [URLs] ❌ Error compilando el patrón regex para '{key}': {e}")
        return patterns

    # --- MÉTODO 'RUN' MODIFICADO ---
    def run(self, base_output_dir):
        """
        Orquesta la ejecución: Itera sobre cada host, busca sus URLs,
        las clasifica y las guarda antes de pasar al siguiente host.
        """
        if not self.hosts:
            logger.warning("   [URLs] No hay hosts en la lista para procesar.")
            return

        logger.info(f"   [URLs] Iniciando procesamiento para {len(self.hosts)} hosts...")
        
        # Bucle principal que procesa un host a la vez
        for host in self.hosts:
            logger.info(f"\n   [URLs] -------------------------------------------------")
            logger.info(f"   [URLs] 🎯 Procesando host: {host}")
            
            # 1. Recolecta URLs SOLO para el host actual
            host_specific_urls = self._run_url_finders(host)
            
            if not host_specific_urls:
                logger.info(f"   [URLs] No se encontraron URLs para {host}.")
                continue # Pasa al siguiente host

            logger.info(f"   [URLs] Se encontraron {len(host_specific_urls)} URLs para {host}. Guardando...")

            try:
                # 2. Prepara el directorio de salida para este host
                host_dir_name = host.replace(':', '_').replace('/', '_')
                host_output_dir = os.path.join(base_output_dir, host_dir_name)
                os.makedirs(host_output_dir, exist_ok=True)
                
                # 3. Clasifica las URLs encontradas
                categorized = self._categorize_urls(list(host_specific_urls))
                
                # 4. Guarda los archivos clasificados para este host
                self._save_categorized_files(host_output_dir, categorized)
                logger.info(f"   [URLs] ✅ Resultados para '{host}' guardados en: {host_output_dir}")

            except Exception as e:
                logger.error(f"   [URLs] ❌ Falló el procesamiento para el host '{host}': {e}")
        
        logger.info(f"   [URLs] -------------------------------------------------")
        logger.info(f"   [URLs] Procesamiento de todos los hosts finalizado.")

    def _run_url_finders(self, single_host):
        """
        Ejecuta herramientas como gau y katana para un único host/dominio.
        Devuelve un conjunto (set) de URLs encontradas.
        """
        host_urls = set()
        tools = {
            "gau": self.config.get('TOOLS', 'GAU_PATH', fallback='gau'),
            "katana": self.config.get('TOOLS', 'KATANA_PATH', fallback='katana')
        }
        
        commands = {
            "gau": f"echo {single_host} | {tools['gau']}",
            "katana": f"{tools['katana']} -u {single_host} -silent -d 2"
        }
        
        for tool_name, command in commands.items():
            try:
                logger.info(f"     -> Buscando en '{single_host}' con {tool_name}...")
                stdout = execute_command(command, timeout=180)
                urls = {u.strip() for u in stdout.strip().split('\n') if u.strip()}
                if urls:
                    logger.info(f"     [{tool_name}] Encontró {len(urls)} URLs.")
                    host_urls.update(urls)
            except Exception as e:
                logger.error(f"     [{tool_name}] ❌ Error al ejecutar para '{single_host}': {e}")
        return host_urls

    # El método _process_and_save_by_host ya no es necesario, su lógica se movió al método run.
    # Los otros métodos (_is_url_from_host, _categorize_urls, _save_categorized_files) se mantienen igual.

    def _categorize_urls(self, url_list):
        """Aplica los patrones regex a una lista de URLs para clasificarlas."""
        categorized = {
            "salidatodo": set(url_list), "dataExtensiones": set(), "imagenes": set(),
            "jsfiles": set(), "openRedirect": set(), "xss": set(), "sql": set(), "keys": set()
        }
        pattern_map = {
            "dataExtensiones": "sensitive_ext", "imagenes": "image_ext", "jsfiles": "js_files",
            "openRedirect": "open_redirect", "xss": "xss", "sql": "sqli", "keys": "keys"
        }
        for url in url_list:
            for filename, pattern_key in pattern_map.items():
                if pattern_key in self.patterns and self.patterns[pattern_key].search(url):
                    categorized[filename].add(url)
        return categorized

    def _save_categorized_files(self, output_dir, categorized_urls):
        """Escribe los resultados categorizados en sus respectivos archivos .txt."""
        for filename, urls_set in categorized_urls.items():
            if not urls_set: continue
            
            file_path = os.path.join(output_dir, f"{filename}.txt")
            try:
                with open(file_path, 'w') as f:
                    f.write('\n'.join(sorted(list(urls_set))))
            except IOError as e:
                 logger.error(f"     ❌ No se pudo guardar el archivo {file_path}: {e}")