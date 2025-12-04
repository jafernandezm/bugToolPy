# be/modules/utils/helpers.py

import subprocess
import os
import logging

logger = logging.getLogger(__name__)

def update_execution_environment():
    """
    Actualiza la variable PATH para incluir $HOME/go/bin.
    Esto es crucial para que herramientas instaladas con 'go install' sean encontradas.
    """
    go_bin_path = os.path.join(os.path.expanduser('~'), 'go', 'bin')
    current_path = os.environ.get('PATH', '')
    
    if go_bin_path not in current_path:
        # Exporta/añade la ruta de Go al entorno de la ejecución actual
        os.environ['PATH'] = f"{go_bin_path}:{current_path}"
        logger.debug(f"PATH de ejecución actualizado para incluir: {go_bin_path}")

def execute_command(command, timeout=30000):
    """
    Ejecuta un comando de shell y retorna la salida estándar.
    Lanza una excepción en caso de error o timeout.
    """
    # 1. Aseguramos que el PATH esté actualizado antes de ejecutar cualquier cosa
    update_execution_environment() 
    
    try:
        logger.debug(f"Ejecutando comando: {command}")
        
        process = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=True, # Lanza CalledProcessError si el código de salida no es cero
            env=os.environ.copy() # Usamos el entorno modificado
        )
        return process.stdout
    except subprocess.CalledProcessError as e:
        logger.warning(f"Comando falló con código {e.returncode}. Stderr: {e.stderr.strip()}")
        raise Exception(f"Fallo en herramienta externa: {command.split()[0]}") from e
    except subprocess.TimeoutExpired:
        logger.warning(f"Comando excedió el tiempo límite ({timeout}s): {command}")
        raise Exception("Timeout en herramienta externa")
    except FileNotFoundError:
        logger.error(f"Herramienta no encontrada: Asegúrate de que esté en tu PATH o la ruta sea correcta.")
        raise Exception("Herramienta no encontrada")
    except Exception as e:
        logger.error(f"Error desconocido al ejecutar comando: {e}")
        raise