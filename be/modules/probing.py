import logging
import json
import os
import tempfile
from be.modules.utils.helpers import execute_command
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class ProbingModule:
    # Puertos para los diferentes modos de escaneo
    PORTS_LIGHT = '80,443,8080,8443'
    PORTS_FULL = '80,81,443,3000,8000,8008,8080,8081,8088,8443,8888,9000,9090'

    def __init__(self, target, args, config, subdomains, probing_mode='light'):
        self.target = target
        self.args = args
        self.config = config
        self.subdomains = subdomains
        self.probing_mode = probing_mode
        self.results = {'positives': [], 'negatives': []}
        if self.args.output:
            os.makedirs(self.args.output, exist_ok=True)

    def run(self, output_dir):
        if not self.subdomains:
            logger.info("   [Probing] No hay subdominios para sondear.")
            return self.results

        httpx_path = self.config.get('TOOLS', 'HTTPX_PATH', fallback=None)
        if not httpx_path:
            logger.error("   [Probing] ❌ HTTPX_PATH no está configurado.")
            return self.results

        logger.info(f"   [Probing] Iniciando sondeo ({self.probing_mode.upper()}) de {len(self.subdomains)} objetivos...")

        with tempfile.NamedTemporaryFile(mode='w+', delete=True, prefix='targets_') as tmpfile:
            tmpfile.write('\n'.join(self.subdomains))
            tmpfile.flush()
            self._run_httpx(httpx_path, tmpfile.name, output_dir)

        return self.results

    def _run_httpx(self, httpx_path, input_file, output_dir):
        """
        Ejecuta httpx. Para el modo 'fast', usa el comando más simple posible para obtener solo hosts vivos.
        """
        logger.debug(f"   [Probing] Modo de sondeo seleccionado: {self.probing_mode.upper()}")

        command = [
            httpx_path,
            '-l', input_file,
            '-threads', str(self.args.threads),
            '-timeout', str(self.args.timeout),
            '-silent'
        ]

        # --- INICIO DE LA MODIFICACIÓN ---
        if self.probing_mode == 'fast':
            logger.info("   [Httpx] Ejecutando en modo muy rápido (solo hosts vivos)...")
            # No añadimos ningún flag extra. Httpx por defecto solo imprime los hosts que responden.
            command.extend(['-no-color']) # Para asegurar que la salida sea texto limpio
        else:
            # Los modos recon1 y recon2 siguen funcionando como antes
            logger.info("   [Httpx] Ejecutando en modo completo (extracción de datos en JSON)...")
            ports = self.PORTS_FULL if self.probing_mode == 'full' else self.PORTS_LIGHT
            command.extend([
                '-json',
                '-probe',
                '-tech-detect',
                '-title',
                '-content-length',
                '-cdn',
                '-cname',
                '-ports', ports,
                '-retries', '1'
            ])
        # --- FIN DE LA MODIFICACIÓN ---

        logger.debug(f"   [Httpx] Comando final: {' '.join(command)}")

        try:
            stdout = execute_command(' '.join(command), timeout=None)

            if self.probing_mode != 'fast':
                self._parse_httpx_output(stdout)
                self._save_results_json(output_dir)
            else:
                print("\n--- Resultados de Httpx (Hosts Vivos) ---\n")
                print(stdout)
                print("----------------------------------------\n")
                self._save_results_text(stdout, output_dir)

        except Exception as e:
            logger.error(f"   [Probing] ❌ Error al ejecutar httpx: {e}")

    def _parse_httpx_output(self, json_lines_output):
        # Esta función no cambia, solo se usa para recon1 y recon2
        for line in json_lines_output.split('\n'):
            line = line.strip()
            if not line: continue
            try:
                result = json.loads(line)
                structured_data = {
                    'url': result.get('url', ''), 'host': result.get('input', ''),
                    'ip': result.get('host', ''), 'scheme': result.get('scheme', ''),
                    'port': int(result.get('port', 0)), 'status_code': int(result.get('status_code', 0)),
                    'title': result.get('title', ''), 'tech': ', '.join(sorted(set(result.get('tech', [])))),
                    'content_type': result.get('content_type', ''),
                    'response_size': int(result.get('content_length', 0)),
                    'cname': ', '.join(result.get('cname', [])), 'cdn': result.get('cdn', False)
                }
                if not result.get('failed', True) and result.get('status_code', 0) > 0:
                    self.results['positives'].append(structured_data)
                else:
                    self.results['negatives'].append(structured_data)
            except json.JSONDecodeError as e:
                logger.warning(f"   [Probing] Error al decodificar línea JSON de httpx: {e}.")

    # --- INICIO DE LA FUNCIÓN MODIFICADA ---
    def _save_results_text(self, text_output, output_dir):
        """Guarda la salida de texto plano de httpx directamente en positives.txt."""
        
        # La salida ya es una lista limpia de URLs vivas, una por línea.
        # Nos aseguramos de filtrar líneas vacías que puedan aparecer.
        positives = [line for line in text_output.strip().split('\n') if line]

        base_name = self.target.replace('.', '_')

        # Guardar positivos
        pos_txt_path = os.path.join(output_dir, f"{base_name}_positives.txt")
        with open(pos_txt_path, 'w') as f:
            f.write('\n'.join(sorted(positives)))
        logger.info(f"   [Probing] {len(positives)} hosts vivos guardados en: {pos_txt_path}")

        # Guardar un archivo de negativos vacío para mantener la consistencia en la estructura de archivos
        neg_txt_path = os.path.join(output_dir, f"{base_name}_negativos.txt")
        with open(neg_txt_path, 'w') as f:
            f.write('') # Escribir un archivo vacío
        logger.info(f"   [Probing] 0 resultados negativos guardados en: {neg_txt_path}")
    # --- FIN DE LA FUNCIÓN MODIFICADA ---

    def _save_results_json(self, output_dir):
        # Esta función no cambia, solo se usa para recon1 y recon2
        base_name = self.target.replace('.', '_')
        pos_json_path = os.path.join(output_dir, f"{base_name}_positives.json")
        pos_txt_path = os.path.join(output_dir, f"{base_name}_positives.txt")
        with open(pos_json_path, 'w') as f_json:
            json.dump(self.results['positives'], f_json, indent=4)
        with open(pos_txt_path, 'w') as f_txt:
            urls = sorted([r['url'] for r in self.results['positives']])
            f_txt.write('\n'.join(urls))
        neg_json_path = os.path.join(output_dir, f"{base_name}_negativos.json")
        neg_txt_path = os.path.join(output_dir, f"{base_name}_negativos.txt")
        with open(neg_json_path, 'w') as f_json:
            json.dump(self.results['negatives'], f_json, indent=4)
        with open(neg_txt_path, 'w') as f_txt:
            hosts = sorted(list(set([r['host'] for r in self.results['negatives']])))
            f_txt.write('\n'.join(hosts))
        logger.info(f"   [Probing] Resultados completos guardados en: {output_dir}")