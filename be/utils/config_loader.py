# be/utils/config_loader.py

import configparser
import os
import logging

logger = logging.getLogger(__name__)

def load_config(config_file=os.path.join(os.path.dirname(os.path.abspath(__file__)), '../../configs/default.conf')):
    """Carga la configuración de la herramienta desde el archivo default.conf."""
    config = configparser.ConfigParser()
    
    if not os.path.exists(config_file):
        logger.error(f"Archivo de configuración no encontrado: {config_file}")
        return {}

    try:
        config.read(config_file)
        logger.debug(f"Configuración cargada desde {config_file}")
    except configparser.Error as e:
        logger.error(f"Error al parsear el archivo de configuración: {e}")
        return {}
        
    return config