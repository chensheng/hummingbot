import asyncio
import logging
from pathlib import Path
from typing import Dict, Optional

from hummingbot.client.config.config_crypt import PASSWORD_VERIFICATION_PATH, BaseSecretsManager, validate_password
from hummingbot.client.config.config_helpers import (
    ClientConfigAdapter,
    api_keys_from_connector_config_map,
    connector_name_from_file,
    get_connector_config_yml_path,
    list_connector_configs,
    load_connector_config_map_from_file,
    reset_connector_hb_config,
    save_to_yml,
    update_connector_hb_config,
)

# from hummingbot.core.utils.async_call_scheduler import AsyncCallScheduler
# from hummingbot.core.utils.async_utils import safe_ensure_future
from hummingbot.logger import HummingbotLogger


class Security:
    __instance = None
    secrets_manager: Optional[BaseSecretsManager] = None
    _secure_configs = {}
    _decryption_done = asyncio.Event()
    
    # Multi-instance support
    _instance_configs: Dict[str, Dict] = {}  # Maps instance_id to secure_configs
    _instance_decryption_done: Dict[str, asyncio.Event] = {}  # Maps instance_id to decryption_done events
    _instance_connectors_paths: Dict[str, str] = {}  # Maps instance_id to custom connectors paths

    _logger: Optional[HummingbotLogger] = None

    @classmethod
    def logger(cls) -> HummingbotLogger:
        if cls._logger is None:
            cls._logger = logging.getLogger(__name__)
        return cls._logger

    @staticmethod
    def new_password_required() -> bool:
        return not PASSWORD_VERIFICATION_PATH.exists()

    @classmethod
    def any_secure_configs(cls, instance_id: Optional[str] = None):
        if instance_id is not None:
            return len(cls._instance_configs.get(instance_id, {})) > 0
        return len(cls._secure_configs) > 0

    @staticmethod
    def connector_config_file_exists(connector_name: str, instance_id: Optional[str] = None) -> bool:
        connector_configs_path = Security._get_connector_config_yml_path(connector_name, instance_id)
        return connector_configs_path.exists()

    @classmethod
    def _get_connector_config_yml_path(cls, connector_name: str, instance_id: Optional[str] = None) -> Path:
        if instance_id is not None and instance_id in cls._instance_connectors_paths:
            # Use instance-specific connectors path
            connector_path = Path(cls._instance_connectors_paths[instance_id]) / f"{connector_name}.yml"
            return connector_path
        # Use default behavior
        return get_connector_config_yml_path(connector_name)

    @classmethod
    def set_instance_connectors_path(cls, instance_id: str, connectors_path: str):
        """Set a custom connectors path for a specific instance."""
        cls._instance_connectors_paths[instance_id] = connectors_path

    @classmethod
    def login(cls, secrets_manager: BaseSecretsManager, instance_id: Optional[str] = None) -> bool:
        if not validate_password(secrets_manager):
            return False
        if instance_id is not None:
            # For multi-instance mode, store secrets manager per instance
            # We'll handle decryption separately for each instance
            pass
        else:
            # Global mode
            cls.secrets_manager = secrets_manager
            cls.decrypt_all()
        # coro = AsyncCallScheduler.shared_instance().call_async(cls.decrypt_all, timeout_seconds=30)
        # safe_ensure_future(coro)
        return True

    @classmethod
    def decrypt_all(cls, instance_id: Optional[str] = None):
        if instance_id is not None:
            # Multi-instance mode
            if instance_id not in cls._instance_configs:
                cls._instance_configs[instance_id] = {}
            if instance_id not in cls._instance_decryption_done:
                cls._instance_decryption_done[instance_id] = asyncio.Event()
                
            cls._instance_configs[instance_id].clear()
            cls._instance_decryption_done[instance_id].clear()
            encrypted_files = cls._list_connector_configs(instance_id)
            for file in encrypted_files:
                cls.decrypt_connector_config(file, instance_id)
            cls._instance_decryption_done[instance_id].set()
        else:
            # Global mode
            cls._secure_configs.clear()
            cls._decryption_done.clear()
            encrypted_files = list_connector_configs()
            for file in encrypted_files:
                cls.decrypt_connector_config(file)
            cls._decryption_done.set()

    @classmethod
    def _list_connector_configs(cls, instance_id: Optional[str] = None) -> List[Path]:
        from hummingbot.client.config.config_helpers import CONNECTORS_CONF_DIR_PATH
        from os import scandir
        
        if instance_id is not None and instance_id in cls._instance_connectors_paths:
            # Use instance-specific connectors path
            connectors_dir = cls._instance_connectors_paths[instance_id]
        else:
            # Use default connectors path
            connectors_dir = CONNECTORS_CONF_DIR_PATH
            
        connector_configs = [
            Path(f.path) for f in scandir(str(connectors_dir))
            if f.is_file() and not f.name.startswith("_") and not f.name.startswith(".")
        ]
        return connector_configs

    @classmethod
    def decrypt_connector_config(cls, file_path: Path, instance_id: Optional[str] = None):
        connector_name = connector_name_from_file(file_path)
        connector_config = load_connector_config_map_from_file(file_path)
        if instance_id is not None:
            # Multi-instance mode
            if instance_id not in cls._instance_configs:
                cls._instance_configs[instance_id] = {}
            cls._instance_configs[instance_id][connector_name] = connector_config
        else:
            # Global mode
            cls._secure_configs[connector_name] = connector_config
        update_connector_hb_config(connector_config)

    @classmethod
    def update_secure_config(cls, connector_config: ClientConfigAdapter, instance_id: Optional[str] = None):
        connector_name = connector_config.connector
        file_path = cls._get_connector_config_yml_path(connector_name, instance_id)
        save_to_yml(file_path, connector_config)
        update_connector_hb_config(connector_config)
        if instance_id is not None:
            # Multi-instance mode
            if instance_id not in cls._instance_configs:
                cls._instance_configs[instance_id] = {}
            cls._instance_configs[instance_id][connector_name] = connector_config
        else:
            # Global mode
            cls._secure_configs[connector_name] = connector_config

    @classmethod
    def remove_secure_config(cls, connector_name: str, instance_id: Optional[str] = None):
        file_path = cls._get_connector_config_yml_path(connector_name, instance_id)
        file_path.unlink(missing_ok=True)
        reset_connector_hb_config(connector_name)
        if instance_id is not None:
            # Multi-instance mode
            if instance_id in cls._instance_configs and connector_name in cls._instance_configs[instance_id]:
                cls._instance_configs[instance_id].pop(connector_name)
        else:
            # Global mode
            cls._secure_configs.pop(connector_name, None)

    @classmethod
    def is_decryption_done(cls, instance_id: Optional[str] = None):
        if instance_id is not None:
            # Multi-instance mode
            if instance_id in cls._instance_decryption_done:
                return cls._instance_decryption_done[instance_id].is_set()
            return False
        # Global mode
        return cls._decryption_done.is_set()

    @classmethod
    def decrypted_value(cls, key: str, instance_id: Optional[str] = None) -> Optional[ClientConfigAdapter]:
        if instance_id is not None:
            # Multi-instance mode
            if instance_id in cls._instance_configs:
                return cls._instance_configs[instance_id].get(key, None)
            return None
        # Global mode
        return cls._secure_configs.get(key, None)

    @classmethod
    def all_decrypted_values(cls, instance_id: Optional[str] = None) -> Dict[str, ClientConfigAdapter]:
        if instance_id is not None:
            # Multi-instance mode
            return cls._instance_configs.get(instance_id, {}).copy()
        # Global mode
        return cls._secure_configs.copy()

    @classmethod
    async def wait_til_decryption_done(cls, instance_id: Optional[str] = None):
        if instance_id is not None:
            # Multi-instance mode
            if instance_id not in cls._instance_decryption_done:
                cls._instance_decryption_done[instance_id] = asyncio.Event()
            await cls._instance_decryption_done[instance_id].wait()
        else:
            # Global mode
            await cls._decryption_done.wait()

    @classmethod
    def api_keys(cls, connector_name: str, instance_id: Optional[str] = None) -> Dict[str, Optional[str]]:
        connector_config = cls.decrypted_value(connector_name, instance_id)
        keys = (
            api_keys_from_connector_config_map(connector_config)
            if connector_config is not None
            else {}
        )
        return keys