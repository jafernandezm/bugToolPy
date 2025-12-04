# be/modules/recon.py

import logging
from be.modules.utils.helpers import execute_command
import os
import json
import tempfile
import requests

logger = logging.getLogger(__name__)

class ReconModule:
    # --- CAMBIO CLAVE ---
    # Definimos un tiempo límite FIJO y GENEROSO para todas las herramientas de reconocimiento.
    # 5 minutos = 300 segundos.
    RECON_TOOL_TIMEOUT = 300 
    API_TIMEOUT = 320 # Mantenemos un timeout razonable de 2 minutos para las APIs

    def __init__(self, target, args, config, output_dir=None): 
        self.target = target
        self.args = args
        self.config = config
        self.output_dir = output_dir 
        self.results = {'subdomains': []} 

    def run(self):
        """Ejecuta todos los pasos de reconocimiento pasivo."""
        logger.info(f"   [Recon] Iniciando Reconocimiento Pasivo...")
        self.passive_subdomain_discovery()
        
        unique_subdomains = list(set(self.results['subdomains']))
        clean_subdomains = [sub for sub in unique_subdomains if '*' not in sub]
        filtered_count = len(unique_subdomains) - len(clean_subdomains)
        if filtered_count > 0:
            logger.info(f"   [Recon] Se filtraron {filtered_count} subdominios con wildcards para evitar errores.")
        self.results['subdomains'] = sorted(clean_subdomains)
        
        count = len(self.results['subdomains'])
        logger.info(f"   [Recon] Total de subdominios únicos y válidos encontrados: {count}")
        
        if self.output_dir and count > 0:
            self._save_recon_results() 
        return self.results

    def passive_subdomain_discovery(self):
        """Ejecuta las herramientas y APIs de reconocimiento."""
        try:
            tools = {
                'subdominator': self.config.get('TOOLS', 'SUBDOMINATOR_PATH'),
                'subfinder': self.config.get('TOOLS', 'SUBFINDER_PATH', fallback='subfinder'),
                'amass': self.config.get('TOOLS', 'AMASS_PATH', fallback='amass'),
            }
        except Exception:
            logger.error("   [Config] Error al cargar rutas de herramientas desde la configuración.")
            return

        self._run_subdominator(tools['subdominator'])
        self._run_subfinder(tools['subfinder'])
        self._run_amass(tools['amass'])
        self._query_urlscan_io()
        self._query_crt_sh()
        
    # --- Métodos de Ejecución de Herramientas (TODOS USAN EL TIMEOUT FIJO) ---

    def _run_subdominator(self, path):
        if not os.path.isfile(path):
             logger.error(f"   [Subdominator] ❌ Error: El ejecutable no existe en: {path}")
             return
        subdominator_command = f"{path} -d {self.target}" 
        logger.info(f"   [Subdominator] Ejecutando (Timeout: {self.RECON_TOOL_TIMEOUT}s)...")
        try:
            stdout = execute_command(subdominator_command, timeout=self.RECON_TOOL_TIMEOUT)
            new_subdomains = self._parse_subdominator_output(stdout)
            self.results['subdomains'].extend(new_subdomains)
            logger.info(f"   [Subdominator] Encontrados {len(new_subdomains)} subdominios pasivos.")
        except Exception as e:
            logger.error(f"   [Subdominator] ❌ Error al ejecutar o parsear: {e}")

    def _run_subfinder(self, path):
        with tempfile.NamedTemporaryFile(mode='w+', delete=True) as tmp_file:
            command = [path, "-d", self.target, "-all", "-o", tmp_file.name]
            logger.info(f"   [Subfinder] Ejecutando (Timeout: {self.RECON_TOOL_TIMEOUT}s)...")
            try:
                execute_command(' '.join(command), timeout=self.RECON_TOOL_TIMEOUT)
                tmp_file.seek(0)
                stdout = tmp_file.read()
                new_subdomains = [line.strip() for line in stdout.split('\n') if line.strip()]
                self.results['subdomains'].extend(new_subdomains)
                logger.info(f"   [Subfinder] Encontrados {len(new_subdomains)} subdominios pasivos.")
            except Exception as e:
                logger.error(f"   [Subfinder] ❌ Error al ejecutar o parsear: {e}")

    def _run_amass(self, path):
        command = [path, 'enum', '-passive', '-d', self.target]
        logger.info(f"   [Amass] Ejecutando (Timeout: {self.RECON_TOOL_TIMEOUT}s)...")
        try:
            stdout = execute_command(' '.join(command), timeout=self.RECON_TOOL_TIMEOUT)
            new_subdomains = [line.strip() for line in stdout.split('\n') if line.strip()]
            self.results['subdomains'].extend(new_subdomains)
            logger.info(f"   [Amass] Encontrados {len(new_subdomains)} subdominios pasivos.")
        except Exception as e:
            logger.error(f"   [Amass] ❌ Error al ejecutar o parsear: {e}")

    # --- Métodos de Consulta a APIs ---

    def _query_urlscan_io(self):
        url = f"https://urlscan.io/api/v1/search/?q=domain:{self.target}"
        user_agent = self.args.user_agent or 'BugBounty-Framework/v0.1'
        headers = {'User-Agent': user_agent, 'Accept': 'application/json'}
        logger.info(f"   [Urlscan] Consultando urlscan.io (Timeout: {self.API_TIMEOUT}s)...")
        try:
            response = requests.get(url, headers=headers, timeout=self.API_TIMEOUT)
            response.raise_for_status() 
            data = response.json()
            new_subdomains = set()
            for result in data.get('results', []):
                for key in ['domain', 'host', 'server']:
                    domain = result.get('task', {}).get(key)
                    if domain and domain.endswith(self.target):
                        new_subdomains.add(domain)
                    domain = result.get('page', {}).get(key)
                    if domain and domain.endswith(self.target):
                        new_subdomains.add(domain)
            self.results['subdomains'].extend(list(new_subdomains))
            logger.info(f"   [Urlscan] Encontrados {len(new_subdomains)} subdominios vía API.")
        except requests.exceptions.RequestException as e:
            logger.error(f"   [Urlscan] ❌ Error al conectar o timeout: {e}")
        except json.JSONDecodeError:
            logger.error("   [Urlscan] ❌ Error al decodificar la respuesta JSON.")

    def _query_crt_sh(self):
        url = f"https://crt.sh/?q=%25.{self.target}&output=json"
        user_agent = self.args.user_agent or 'BugBounty-Framework/v0.1'
        headers = {'User-Agent': user_agent, 'Accept': 'application/json'}
        logger.info(f"   [Crt.sh] Consultando crt.sh (Timeout: {self.API_TIMEOUT}s)...")
        try:
            response = requests.get(url, headers=headers, timeout=self.API_TIMEOUT) 
            response.raise_for_status() 
            new_subdomains = set()
            data = response.json()
            if isinstance(data, list):
                for entry in data:
                    name_value = entry.get('name_value', '')
                    for name in name_value.split('\n'):
                        name = name.strip()
                        if name and name.endswith(self.target):
                            new_subdomains.add(name)
            self.results['subdomains'].extend(list(new_subdomains))
            logger.info(f"   [Crt.sh] Encontrados {len(new_subdomains)} subdominios vía Certificados.")
        except requests.exceptions.RequestException as e:
            logger.error(f"   [Crt.sh] ❌ Error al conectar o timeout: {e}")
        except json.JSONDecodeError:
            logger.error("   [Crt.sh] ❌ Error al decodificar la respuesta JSON.")

    # --- Métodos de Parsing y Guardado (SIN CAMBIOS) ---
    
    def _parse_subdominator_output(self, output):
        subdomains = []
        target_suffix = self.target.lstrip('http://').lstrip('https://')
        for line in output.split('\n'):
            line = line.strip()
            if line and not line.startswith('[') and not line.startswith('_') and not line.startswith('|'):
                if line.endswith(target_suffix):
                    subdomains.append(line)
        return list(set(subdomains)) 
        
    def _save_recon_results(self):
        base_name = self.target.replace('.', '_')
        subdomains = self.results['subdomains']
        
        output_txt = os.path.join(self.output_dir, f"{base_name}_subdomains.txt")
        with open(output_txt, 'w') as f:
            f.write('\n'.join(subdomains))
        
        output_json = os.path.join(self.output_dir, f"{base_name}_subdomains.json")
        with open(output_json, 'w') as f:
            json.dump(subdomains, f, indent=4)
            
        logger.info(f"   [Recon] Subdominios válidos guardados en {output_txt} y {output_json}")